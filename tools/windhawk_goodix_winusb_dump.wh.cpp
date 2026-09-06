// ==WindhawkMod==
// @id              goodix-winusb-dump
// @name            Goodix WinUSB dump
// @description     Capture the Goodix 521D session TLS PSK to psk32.bin.
// @version         1.0.0
// @author          local
// @include         WUDFHost.exe
// @architecture    x86-64
// @compilerOptions -Wl,--export-all-symbols
// ==/WindhawkMod==

#include <windows.h>

typedef LONG_PTR(WINAPI* WbdiPresetPskPskGet_t)(void*, void*, DWORD, DWORD*,
                                                 void*, DWORD);
typedef LONG_PTR(WINAPI* WbdiPresetPskPskSet_t)(void*, void*, DWORD);

static WbdiPresetPskPskGet_t WbdiPresetPskPskGet_Original;
static WbdiPresetPskPskSet_t WbdiPresetPskPskSet_Original;

static const DWORD kMaxCaptureBytes = 1024 * 1024;
static const wchar_t* kPskFile = L"C:\\goodix-capture\\psk32.bin";

static void WriteAll(HANDLE file, const void* data, DWORD bytes) {
    const BYTE* p = static_cast<const BYTE*>(data);
    DWORD remaining = bytes;

    while (remaining > 0) {
        DWORD written = 0;
        if (!WriteFile(file, p, remaining, &written, nullptr) || written == 0) {
            return;
        }

        p += written;
        remaining -= written;
    }
}

static bool IsReadableProtection(DWORD protect) {
    if (protect & PAGE_GUARD) {
        return false;
    }

    protect &= 0xff;
    return protect == PAGE_READONLY || protect == PAGE_READWRITE ||
           protect == PAGE_WRITECOPY || protect == PAGE_EXECUTE_READ ||
           protect == PAGE_EXECUTE_READWRITE ||
           protect == PAGE_EXECUTE_WRITECOPY;
}

static bool IsReadableRange(const void* buffer, SIZE_T length) {
    if (!buffer || length == 0 || length > kMaxCaptureBytes) {
        return false;
    }

    ULONG_PTR start = reinterpret_cast<ULONG_PTR>(buffer);
    ULONG_PTR end = start + length;
    if (end < start) {
        return false;
    }

    ULONG_PTR cursor = start;
    while (cursor < end) {
        MEMORY_BASIC_INFORMATION mbi = {};
        if (!VirtualQuery(reinterpret_cast<void*>(cursor), &mbi, sizeof(mbi))) {
            return false;
        }

        if (mbi.State != MEM_COMMIT || !IsReadableProtection(mbi.Protect)) {
            return false;
        }

        ULONG_PTR regionEnd =
            reinterpret_cast<ULONG_PTR>(mbi.BaseAddress) + mbi.RegionSize;
        if (regionEnd <= cursor) {
            return false;
        }

        cursor = regionEnd < end ? regionEnd : end;
    }

    return true;
}

// Writes exactly 32 bytes to kPskFile under an owner+admins+system-only
// DACL built with core Advapi32 calls only.
// Returns true on success. Never logs or archives the bytes themselves.
static bool WritePskFile(const BYTE* buffer, DWORD length) {
    if (!buffer || length != 32 || !IsReadableRange(buffer, length)) {
        return false;
    }

    BYTE adminSid[SECURITY_MAX_SID_SIZE];
    BYTE systemSid[SECURITY_MAX_SID_SIZE];
    DWORD adminLen = sizeof(adminSid);
    DWORD systemLen = sizeof(systemSid);
    HANDLE token = nullptr;
    BYTE* userBuf = nullptr;
    DWORD userLen = 0;
    PSID userSid = nullptr;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        GetTokenInformation(token, TokenUser, nullptr, 0, &userLen);
        userBuf = static_cast<BYTE*>(
            HeapAlloc(GetProcessHeap(), 0, userLen));
        if (userBuf && GetTokenInformation(token, TokenUser, userBuf,
                                           userLen, &userLen)) {
            userSid = reinterpret_cast<TOKEN_USER*>(userBuf)->User.Sid;
        }
    }

    bool ok = false;
    if (userSid &&
        CreateWellKnownSid(WinBuiltinAdministratorsSid, nullptr, adminSid,
                           &adminLen) &&
        CreateWellKnownSid(WinLocalSystemSid, nullptr, systemSid,
                           &systemLen)) {
        DWORD aclSize =
            sizeof(ACL) + 3 * (sizeof(ACCESS_ALLOWED_ACE) - sizeof(DWORD)) +
            GetLengthSid(userSid) + adminLen + systemLen;
        PACL dacl = static_cast<PACL>(
            HeapAlloc(GetProcessHeap(), 0, aclSize));
        SECURITY_DESCRIPTOR sd;
        if (dacl && InitializeAcl(dacl, aclSize, ACL_REVISION) &&
            AddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, userSid) &&
            AddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, adminSid) &&
            AddAccessAllowedAce(dacl, ACL_REVISION, GENERIC_ALL, systemSid) &&
            InitializeSecurityDescriptor(
                &sd, SECURITY_DESCRIPTOR_REVISION) &&
            SetSecurityDescriptorDacl(&sd, TRUE, dacl, FALSE)) {
            SECURITY_ATTRIBUTES sa = { sizeof(sa), &sd, FALSE };
            HANDLE file = CreateFileW(kPskFile, GENERIC_WRITE, 0, &sa,
                                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                      nullptr);
            if (file != INVALID_HANDLE_VALUE) {
                WriteAll(file, buffer, length);
                CloseHandle(file);
                ok = true;
            }
        }
        if (dacl) {
            HeapFree(GetProcessHeap(), 0, dacl);
        }
    }
    if (userBuf) {
        HeapFree(GetProcessHeap(), 0, userBuf);
    }
    if (token) {
        CloseHandle(token);
    }
    return ok;
}

static LONG_PTR WINAPI WbdiPresetPskPskSet_Hook(void* context,
                                                void* source,
                                                DWORD length) {
    LONG_PTR result = WbdiPresetPskPskSet_Original(context, source, length);

    // The session ctx now holds the driver-verified plaintext PSK. Re-read it
    // deterministically via the original PskGet (pure memcpy-from-ctx, no
    // device I/O, source args ignored) instead of racing the driver's own
    // PskGet call ~200ms later.
    if (result == 0 && context && WbdiPresetPskPskGet_Original) {
        BYTE psk[32];
        DWORD actualLength = sizeof(psk);
        LONG_PTR getResult = WbdiPresetPskPskGet_Original(
            context, psk, sizeof(psk), &actualLength, nullptr, 0);
        if (getResult == 0 && actualLength == sizeof(psk)) {
            if (WritePskFile(psk, actualLength)) {
                Wh_Log(L"PSK captured via PskSet: len %lu written to %s (bytes not logged)",
                       actualLength, kPskFile);
            } else {
                Wh_Log(L"PSK re-read ok but file write failed, len %lu",
                       actualLength);
            }
            SecureZeroMemory(psk, sizeof(psk));
        } else {
            Wh_Log(L"PSK re-read skipped: result %ld len %lu", getResult,
                   actualLength);
        }
    } else if (result == 0) {
        Wh_Log(L"PSK re-read skipped: bad context or missing PskGet original");
    }

    return result;
}

static LONG_PTR WINAPI WbdiPresetPskPskGet_Hook(void* context,
                                                void* outputBuffer,
                                                DWORD outputBufferLength,
                                                DWORD* outputLength,
                                                void* source,
                                                DWORD sourceLength) {
    LONG_PTR result = WbdiPresetPskPskGet_Original(
        context, outputBuffer, outputBufferLength, outputLength, source,
        sourceLength);

    DWORD actualLength = 0;
    if (outputLength && IsReadableRange(outputLength, sizeof(*outputLength))) {
        CopyMemory(&actualLength, outputLength, sizeof(actualLength));
    }

    if (result == 0 && actualLength > 0 &&
        actualLength <= outputBufferLength) {
        if (WritePskFile(static_cast<const BYTE*>(outputBuffer),
                         actualLength)) {
            Wh_Log(L"PSK captured: len %lu written to %s (bytes not logged)",
                   actualLength, kPskFile);
        } else {
            Wh_Log(L"PSK capture skipped: len %lu (expected 32)", actualLength);
        }
    }

    return result;
}

static bool HookInternal(HMODULE module,
                         DWORD_PTR rva,
                         const wchar_t* name,
                         void* hook,
                         void** original) {
    if (!module) {
        Wh_Log(L"missing module for internal hook: %s", name);
        return false;
    }

    void* target = reinterpret_cast<void*>(
        reinterpret_cast<BYTE*>(module) + rva);
    if (!Wh_SetFunctionHook(target, hook, original)) {
        Wh_Log(L"failed to hook internal: %s at RVA 0x%Ix", name, rva);
        return false;
    }

    Wh_Log(L"hooked internal: %s at RVA 0x%Ix", name, rva);
    return true;
}

BOOL Wh_ModInit() {
    // Wbdi.dll may load after mod init on a fresh host (it did not exist
    // yet at 00:04 in one capture). Wait up to ~30s instead of skipping
    // the internal hooks forever for this process.
    HMODULE wbdi = nullptr;
    for (int i = 0; i < 60 && !wbdi; i++) {
        wbdi = GetModuleHandleW(L"Wbdi.dll");
        if (!wbdi) {
            wbdi = GetModuleHandleW(L"WBDI.DLL");
        }
        if (!wbdi) {
            Sleep(500);
        }
    }
    if (!wbdi) {
        Wh_Log(L"Wbdi.dll is not loaded; PSK hooks skipped");
        return FALSE;
    }

    bool ok = true;
    ok &= HookInternal(wbdi, 0x78658, L"Wbdi!PresetPskPskGet",
                       reinterpret_cast<void*>(WbdiPresetPskPskGet_Hook),
                       reinterpret_cast<void**>(&WbdiPresetPskPskGet_Original));
    ok &= HookInternal(wbdi, 0x787CC, L"Wbdi!PresetPskPskSet",
                       reinterpret_cast<void*>(WbdiPresetPskPskSet_Hook),
                       reinterpret_cast<void**>(&WbdiPresetPskPskSet_Original));

    Wh_Log(L"Goodix PSK capture active, writing to %s", kPskFile);
    return ok ? TRUE : FALSE;
}

void Wh_ModUninit() {
}
