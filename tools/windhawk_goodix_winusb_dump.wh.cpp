// ==WindhawkMod==
// @id              goodix-winusb-dump
// @name            Goodix WinUSB dump
// @description     Dump WinUSB buffers from the Goodix UMDF driver host.
// @version         0.5
// @author          local
// @include         WUDFHost.exe
// @architecture    x86-64
// @compilerOptions -Wl,--export-all-symbols
// ==/WindhawkMod==

#include <windows.h>

typedef void* WINUSB_INTERFACE_HANDLE;

typedef struct _WINUSB_SETUP_PACKET {
    UCHAR RequestType;
    UCHAR Request;
    USHORT Value;
    USHORT Index;
    USHORT Length;
} WINUSB_SETUP_PACKET;

typedef BOOL(WINAPI* WinUsb_ReadPipe_t)(WINUSB_INTERFACE_HANDLE, UCHAR, PUCHAR,
                                        ULONG, PULONG, LPOVERLAPPED);
typedef BOOL(WINAPI* WinUsb_WritePipe_t)(WINUSB_INTERFACE_HANDLE, UCHAR, PUCHAR,
                                         ULONG, PULONG, LPOVERLAPPED);
typedef BOOL(WINAPI* WinUsb_ControlTransfer_t)(WINUSB_INTERFACE_HANDLE,
                                               WINUSB_SETUP_PACKET, PUCHAR,
                                               ULONG, PULONG, LPOVERLAPPED);
typedef BOOL(WINAPI* WinUsb_GetOverlappedResult_t)(WINUSB_INTERFACE_HANDLE,
                                                   LPOVERLAPPED, LPDWORD, BOOL);
typedef BOOL(WINAPI* GetOverlappedResult_t)(HANDLE, LPOVERLAPPED, LPDWORD, BOOL);
typedef BOOL(WINAPI* GetQueuedCompletionStatus_t)(HANDLE, LPDWORD, PULONG_PTR,
                                                  LPOVERLAPPED*, DWORD);
typedef BOOL(WINAPI* GetQueuedCompletionStatusEx_t)(HANDLE, LPOVERLAPPED_ENTRY,
                                                    ULONG, PULONG, DWORD, BOOL);
typedef BOOL(WINAPI* DeviceIoControl_t)(HANDLE, DWORD, LPVOID, DWORD, LPVOID,
                                        DWORD, LPDWORD, LPOVERLAPPED);
typedef DWORD(WINAPI* WaitForSingleObject_t)(HANDLE, DWORD);
typedef DWORD(WINAPI* WaitForSingleObjectEx_t)(HANDLE, DWORD, BOOL);
typedef DWORD(WINAPI* WaitForMultipleObjects_t)(DWORD, const HANDLE*, BOOL,
                                                DWORD);
typedef DWORD(WINAPI* WaitForMultipleObjectsEx_t)(DWORD, const HANDLE*, BOOL,
                                                  DWORD, BOOL);
typedef LONG WH_NTSTATUS;

typedef struct _WH_IO_STATUS_BLOCK {
    union {
        WH_NTSTATUS Status;
        PVOID Pointer;
    };
    ULONG_PTR Information;
} WH_IO_STATUS_BLOCK;

typedef WH_NTSTATUS(NTAPI* NtDeviceIoControlFile_t)(
    HANDLE, HANDLE, PVOID, PVOID, WH_IO_STATUS_BLOCK*, ULONG, PVOID, ULONG,
    PVOID, ULONG);
typedef LONG_PTR(WINAPI* WbdiPresetPskPskGet_t)(void*, void*, DWORD, DWORD*,
                                                void*, DWORD);
typedef LONG_PTR(WINAPI* WbdiIoHubExec_t)(void*, void*);

static WinUsb_ReadPipe_t WinUsb_ReadPipe_Original;
static WinUsb_WritePipe_t WinUsb_WritePipe_Original;
static WinUsb_ControlTransfer_t WinUsb_ControlTransfer_Original;
static WinUsb_GetOverlappedResult_t WinUsb_GetOverlappedResult_Original;
static GetOverlappedResult_t Kernel32_GetOverlappedResult_Original;
static GetOverlappedResult_t KernelBase_GetOverlappedResult_Original;
static GetQueuedCompletionStatus_t Kernel32_GetQueuedCompletionStatus_Original;
static GetQueuedCompletionStatus_t KernelBase_GetQueuedCompletionStatus_Original;
static GetQueuedCompletionStatusEx_t Kernel32_GetQueuedCompletionStatusEx_Original;
static GetQueuedCompletionStatusEx_t KernelBase_GetQueuedCompletionStatusEx_Original;
static DeviceIoControl_t Kernel32_DeviceIoControl_Original;
static DeviceIoControl_t KernelBase_DeviceIoControl_Original;
static NtDeviceIoControlFile_t Ntdll_NtDeviceIoControlFile_Original;
static WbdiPresetPskPskGet_t WbdiPresetPskPskGet_Original;
static WbdiIoHubExec_t WbdiIoHubExec_Original;
static WaitForSingleObject_t Kernel32_WaitForSingleObject_Original;
static WaitForSingleObject_t KernelBase_WaitForSingleObject_Original;
static WaitForSingleObjectEx_t Kernel32_WaitForSingleObjectEx_Original;
static WaitForSingleObjectEx_t KernelBase_WaitForSingleObjectEx_Original;
static WaitForMultipleObjects_t Kernel32_WaitForMultipleObjects_Original;
static WaitForMultipleObjects_t KernelBase_WaitForMultipleObjects_Original;
static WaitForMultipleObjectsEx_t Kernel32_WaitForMultipleObjectsEx_Original;
static WaitForMultipleObjectsEx_t KernelBase_WaitForMultipleObjectsEx_Original;

static const DWORD kMaxCaptureBytes = 1024 * 1024;
static const WH_NTSTATUS kStatusPending = 0x00000103;
static const wchar_t* kRoot = L"C:\\goodix-capture\\windhawk-winusb";
static const wchar_t* kBuffers = L"C:\\goodix-capture\\windhawk-winusb\\buffers";
static const wchar_t* kEvents = L"C:\\goodix-capture\\windhawk-winusb\\events.jsonl";

struct PendingTransfer {
    LPOVERLAPPED overlapped;
    HANDLE eventHandle;
    PUCHAR buffer;
    ULONG requestedLength;
    DWORD ioctlCode;
    UCHAR pipeId;
    bool inUse;
    char api[32];
    char direction[16];
    wchar_t apiW[32];
    wchar_t directionW[16];
};

struct CaptureItem {
    CaptureItem* next;
    LONG seq;
    DWORD pid;
    DWORD tid;
    char utc[40];
    char api[32];
    char direction[16];
    wchar_t apiW[32];
    wchar_t directionW[16];
    UCHAR pipeId;
    DWORD ioctlCode;
    DWORD requestedLength;
    DWORD actualLength;
    BOOL ok;
    DWORD lastError;
    bool pending;
    BYTE data[1];
};

static volatile LONG g_sequence;
static volatile LONG g_acceptingCaptures;
static volatile LONG g_workerStop;
static CRITICAL_SECTION g_lock;
static bool g_lockReady;
static HANDLE g_queueEvent;
static HANDLE g_workerThread;
static CaptureItem* g_queueHead;
static CaptureItem* g_queueTail;
static PendingTransfer g_pending[128];

static void CopyAnsi(char* dst, DWORD dstChars, const char* src) {
    if (!dst || dstChars == 0) {
        return;
    }

    DWORD i = 0;
    while (src && src[i] && i + 1 < dstChars) {
        dst[i] = src[i];
        i++;
    }

    dst[i] = 0;
}

static void CopyWide(wchar_t* dst, DWORD dstChars, const wchar_t* src) {
    if (!dst || dstChars == 0) {
        return;
    }

    DWORD i = 0;
    while (src && src[i] && i + 1 < dstChars) {
        dst[i] = src[i];
        i++;
    }

    dst[i] = 0;
}

static void EnsureCaptureDirs() {
    CreateDirectoryW(L"C:\\goodix-capture", nullptr);
    CreateDirectoryW(kRoot, nullptr);
    CreateDirectoryW(kBuffers, nullptr);
}

static void GetUtcTimestamp(char* buffer, DWORD chars) {
    if (!buffer || chars == 0) {
        return;
    }

    SYSTEMTIME st;
    GetSystemTime(&st);
    wsprintfA(buffer, "%04u-%02u-%02uT%02u:%02u:%02u.%03uZ", st.wYear,
              st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
              st.wMilliseconds);
}

static void WideToUtf8(const wchar_t* src, char* dst, DWORD dstBytes) {
    if (!dst || dstBytes == 0) {
        return;
    }

    dst[0] = 0;
    if (!src) {
        return;
    }

    WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, dstBytes, nullptr, nullptr);
    dst[dstBytes - 1] = 0;
}

static void JsonEscape(const char* src, char* dst, DWORD dstBytes) {
    if (!dst || dstBytes == 0) {
        return;
    }

    DWORD out = 0;
    for (DWORD i = 0; src && src[i] && out + 1 < dstBytes; i++) {
        char c = src[i];
        if ((c == '\\' || c == '"') && out + 2 < dstBytes) {
            dst[out++] = '\\';
            dst[out++] = c;
        } else if (c == '\r' && out + 2 < dstBytes) {
            dst[out++] = '\\';
            dst[out++] = 'r';
        } else if (c == '\n' && out + 2 < dstBytes) {
            dst[out++] = '\\';
            dst[out++] = 'n';
        } else {
            dst[out++] = c;
        }
    }

    dst[out] = 0;
}

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

static bool ReadMemoryValue(const void* base,
                            SIZE_T offset,
                            void* out,
                            SIZE_T outLength) {
    const BYTE* address = static_cast<const BYTE*>(base) + offset;
    if (!out || !IsReadableRange(address, outLength)) {
        return false;
    }

    CopyMemory(out, address, outLength);
    return true;
}

static DWORD ReadU32Field(const void* base, SIZE_T offset) {
    DWORD value = 0;
    ReadMemoryValue(base, offset, &value, sizeof(value));
    return value;
}

static WORD ReadU16Field(const void* base, SIZE_T offset) {
    WORD value = 0;
    ReadMemoryValue(base, offset, &value, sizeof(value));
    return value;
}

static void* ReadPointerField(const void* base, SIZE_T offset) {
    void* value = nullptr;
    ReadMemoryValue(base, offset, &value, sizeof(value));
    return value;
}

static bool WriteBinaryFile(const wchar_t* path, const BYTE* buffer, DWORD length) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return false;
    }

    if (buffer && length > 0) {
        WriteAll(file, buffer, length);
    }

    CloseHandle(file);
    return true;
}

static char HexChar(BYTE value) {
    value &= 0x0f;
    return static_cast<char>(value < 10 ? '0' + value : 'a' + (value - 10));
}

static void WriteHexFile(const wchar_t* path, const BYTE* buffer, DWORD length) {
    HANDLE file = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, nullptr,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    for (DWORD offset = 0; offset < length; offset += 16) {
        char line[96];
        int pos = wsprintfA(line, "%08lx  ", offset);

        for (DWORD i = 0; i < 16; i++) {
            if (offset + i < length) {
                BYTE b = buffer[offset + i];
                line[pos++] = HexChar(b >> 4);
                line[pos++] = HexChar(b);
            } else {
                line[pos++] = ' ';
                line[pos++] = ' ';
            }
            line[pos++] = (i == 7) ? '-' : ' ';
        }

        line[pos++] = ' ';
        for (DWORD i = 0; i < 16 && offset + i < length; i++) {
            BYTE b = buffer[offset + i];
            line[pos++] = (b >= 0x20 && b <= 0x7e) ? static_cast<char>(b) : '.';
        }
        line[pos++] = '\r';
        line[pos++] = '\n';

        WriteAll(file, line, static_cast<DWORD>(pos));
    }

    CloseHandle(file);
}

static void AppendEventJson(const CaptureItem* item,
                            const wchar_t* binPath,
                            const wchar_t* hexPath) {
    char binUtf8[MAX_PATH * 3];
    char hexUtf8[MAX_PATH * 3];
    char binJson[MAX_PATH * 3 * 2];
    char hexJson[MAX_PATH * 3 * 2];
    char line[2048];

    WideToUtf8(binPath, binUtf8, sizeof(binUtf8));
    WideToUtf8(hexPath, hexUtf8, sizeof(hexUtf8));
    JsonEscape(binUtf8, binJson, sizeof(binJson));
    JsonEscape(hexUtf8, hexJson, sizeof(hexJson));

    int len = wsprintfA(
        line,
        "{\"seq\":%ld,\"utc\":\"%s\",\"pid\":%lu,\"tid\":%lu,"
        "\"api\":\"%s\",\"direction\":\"%s\",\"pipe\":%u,"
        "\"ioctl\":\"0x%08lx\",\"requested_len\":%lu,\"actual_len\":%lu,\"ok\":%s,"
        "\"last_error\":%lu,\"pending\":%s,\"buffer_bin\":\"%s\","
        "\"buffer_hex\":\"%s\"}\r\n",
        item->seq, item->utc, item->pid, item->tid, item->api,
        item->direction, item->pipeId, item->ioctlCode, item->requestedLength,
        item->actualLength, item->ok ? "true" : "false", item->lastError,
        item->pending ? "true" : "false", binJson, hexJson);

    HANDLE file = CreateFileW(kEvents, FILE_APPEND_DATA, FILE_SHARE_READ, nullptr,
                              OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) {
        return;
    }

    WriteAll(file, line, static_cast<DWORD>(len));
    CloseHandle(file);
}

static CaptureItem* PopCapture() {
    if (!g_lockReady) {
        return nullptr;
    }

    EnterCriticalSection(&g_lock);
    CaptureItem* item = g_queueHead;
    if (item) {
        g_queueHead = item->next;
        if (!g_queueHead) {
            g_queueTail = nullptr;
        }
        item->next = nullptr;
    }
    LeaveCriticalSection(&g_lock);

    return item;
}

static bool QueueIsEmpty() {
    if (!g_lockReady) {
        return true;
    }

    EnterCriticalSection(&g_lock);
    bool empty = g_queueHead == nullptr;
    LeaveCriticalSection(&g_lock);
    return empty;
}

static void WriteCaptureItem(CaptureItem* item) {
    if (!item) {
        return;
    }

    EnsureCaptureDirs();

    wchar_t binPath[MAX_PATH];
    wchar_t hexPath[MAX_PATH];

    wsprintfW(binPath, L"%s\\p%lu-t%lu-%06ld-%s-%s-pipe%02x-len%06lu.bin",
              kBuffers, item->pid, item->tid, item->seq, item->directionW,
              item->apiW, item->pipeId, item->actualLength);
    wsprintfW(hexPath, L"%s\\p%lu-t%lu-%06ld-%s-%s-pipe%02x-len%06lu.hex",
              kBuffers, item->pid, item->tid, item->seq, item->directionW,
              item->apiW, item->pipeId, item->actualLength);

    WriteBinaryFile(binPath, item->data, item->actualLength);
    WriteHexFile(hexPath, item->data, item->actualLength);
    AppendEventJson(item, binPath, hexPath);
}

static DWORD WINAPI CaptureWorkerThread(void*) {
    while (true) {
        WaitForSingleObject(g_queueEvent, INFINITE);

        CaptureItem* item = nullptr;
        while ((item = PopCapture()) != nullptr) {
            WriteCaptureItem(item);
            HeapFree(GetProcessHeap(), 0, item);
        }

        if (InterlockedCompareExchange(&g_workerStop, 0, 0) && QueueIsEmpty()) {
            break;
        }
    }

    return 0;
}

static void EnqueueBufferWithIoctl(const char* api,
                                   const wchar_t* apiW,
                                   const char* direction,
                                   const wchar_t* directionW,
                                   UCHAR pipeId,
                                   DWORD ioctlCode,
                                   const BYTE* buffer,
                                   DWORD requestedLength,
                                   DWORD actualLength,
                                   BOOL ok,
                                   DWORD lastError,
                                   bool pending) {
    DWORD savedLastError = GetLastError();

    if (!buffer || actualLength == 0 || actualLength > kMaxCaptureBytes ||
        !IsReadableRange(buffer, actualLength) || !g_lockReady || !g_queueEvent ||
        !InterlockedCompareExchange(&g_acceptingCaptures, 0, 0)) {
        SetLastError(savedLastError);
        return;
    }

    SIZE_T allocSize = sizeof(CaptureItem) + actualLength - 1;
    CaptureItem* item = static_cast<CaptureItem*>(
        HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, allocSize));
    if (!item) {
        SetLastError(savedLastError);
        return;
    }

    item->seq = InterlockedIncrement(&g_sequence);
    item->pid = GetCurrentProcessId();
    item->tid = GetCurrentThreadId();
    item->pipeId = pipeId;
    item->ioctlCode = ioctlCode;
    item->requestedLength = requestedLength;
    item->actualLength = actualLength;
    item->ok = ok;
    item->lastError = lastError;
    item->pending = pending;
    GetUtcTimestamp(item->utc, ARRAYSIZE(item->utc));
    CopyAnsi(item->api, ARRAYSIZE(item->api), api);
    CopyAnsi(item->direction, ARRAYSIZE(item->direction), direction);
    CopyWide(item->apiW, ARRAYSIZE(item->apiW), apiW);
    CopyWide(item->directionW, ARRAYSIZE(item->directionW), directionW);
    CopyMemory(item->data, buffer, actualLength);

    EnterCriticalSection(&g_lock);
    if (g_queueTail) {
        g_queueTail->next = item;
    } else {
        g_queueHead = item;
    }
    g_queueTail = item;
    LeaveCriticalSection(&g_lock);

    SetEvent(g_queueEvent);
    SetLastError(savedLastError);
}

static void EnqueueBuffer(const char* api,
                          const wchar_t* apiW,
                          const char* direction,
                          const wchar_t* directionW,
                          UCHAR pipeId,
                          const BYTE* buffer,
                          DWORD requestedLength,
                          DWORD actualLength,
                          BOOL ok,
                          DWORD lastError,
                          bool pending) {
    EnqueueBufferWithIoctl(api, apiW, direction, directionW, pipeId, 0, buffer,
                           requestedLength, actualLength, ok, lastError,
                           pending);
}

static void RememberPendingEx(LPOVERLAPPED overlapped,
                              HANDLE eventHandle,
                              PUCHAR buffer,
                              ULONG requestedLength,
                              UCHAR pipeId,
                              DWORD ioctlCode,
                              const char* api,
                              const wchar_t* apiW,
                              const char* direction,
                              const wchar_t* directionW) {
    DWORD savedLastError = GetLastError();

    if (!overlapped || !buffer || !g_lockReady) {
        SetLastError(savedLastError);
        return;
    }

    EnterCriticalSection(&g_lock);

    DWORD slot = 0;
    for (; slot < ARRAYSIZE(g_pending); slot++) {
        if (!g_pending[slot].inUse || g_pending[slot].overlapped == overlapped) {
            break;
        }
    }

    if (slot < ARRAYSIZE(g_pending)) {
        g_pending[slot].overlapped = overlapped;
        g_pending[slot].eventHandle =
            eventHandle ? eventHandle : (overlapped ? overlapped->hEvent : nullptr);
        g_pending[slot].buffer = buffer;
        g_pending[slot].requestedLength = requestedLength;
        g_pending[slot].ioctlCode = ioctlCode;
        g_pending[slot].pipeId = pipeId;
        g_pending[slot].inUse = true;
        CopyAnsi(g_pending[slot].api, ARRAYSIZE(g_pending[slot].api), api);
        CopyAnsi(g_pending[slot].direction, ARRAYSIZE(g_pending[slot].direction),
                 direction);
        CopyWide(g_pending[slot].apiW, ARRAYSIZE(g_pending[slot].apiW), apiW);
        CopyWide(g_pending[slot].directionW,
                 ARRAYSIZE(g_pending[slot].directionW), directionW);
    }

    LeaveCriticalSection(&g_lock);
    SetLastError(savedLastError);
}

static void RememberPending(LPOVERLAPPED overlapped,
                            PUCHAR buffer,
                            ULONG requestedLength,
                            UCHAR pipeId,
                            const char* api,
                            const wchar_t* apiW,
                            const char* direction,
                            const wchar_t* directionW) {
    RememberPendingEx(overlapped, nullptr, buffer, requestedLength, pipeId, 0,
                      api, apiW, direction, directionW);
}

static bool TakePending(LPOVERLAPPED overlapped, PendingTransfer* out) {
    DWORD savedLastError = GetLastError();

    if (!overlapped || !out || !g_lockReady) {
        SetLastError(savedLastError);
        return false;
    }

    bool found = false;
    EnterCriticalSection(&g_lock);

    for (DWORD i = 0; i < ARRAYSIZE(g_pending); i++) {
        if (g_pending[i].inUse && g_pending[i].overlapped == overlapped) {
            *out = g_pending[i];
            g_pending[i].inUse = false;
            found = true;
            break;
        }
    }

    LeaveCriticalSection(&g_lock);
    SetLastError(savedLastError);
    return found;
}

static bool TakePendingByEvent(HANDLE eventHandle, PendingTransfer* out) {
    DWORD savedLastError = GetLastError();

    if (!eventHandle || !out || !g_lockReady) {
        SetLastError(savedLastError);
        return false;
    }

    bool found = false;
    EnterCriticalSection(&g_lock);

    for (DWORD i = 0; i < ARRAYSIZE(g_pending); i++) {
        if (g_pending[i].inUse && g_pending[i].eventHandle == eventHandle) {
            *out = g_pending[i];
            g_pending[i].inUse = false;
            found = true;
            break;
        }
    }

    LeaveCriticalSection(&g_lock);
    SetLastError(savedLastError);
    return found;
}

static DWORD ClampTransferLength(ULONG_PTR reportedLength, DWORD bufferLength) {
    if (reportedLength > bufferLength) {
        return bufferLength;
    }

    return static_cast<DWORD>(reportedLength);
}

static void EnqueuePendingTransfer(const PendingTransfer& transfer,
                                   DWORD bytesTransferred,
                                   BOOL ok,
                                   DWORD lastError) {
    if (bytesTransferred == 0) {
        return;
    }

    EnqueueBufferWithIoctl(transfer.api, transfer.apiW, transfer.direction,
                           transfer.directionW, transfer.pipeId,
                           transfer.ioctlCode, transfer.buffer,
                           transfer.requestedLength, bytesTransferred, ok,
                           lastError, true);
}

static void ScanCompletedPendingTransfers() {
    DWORD savedLastError = GetLastError();

    struct CompletedTransfer {
        PendingTransfer transfer;
        DWORD bytesTransferred;
        BOOL ok;
        DWORD lastError;
    };

    CompletedTransfer completed[64] = {};
    DWORD completedCount = 0;

    if (!g_lockReady) {
        SetLastError(savedLastError);
        return;
    }

    EnterCriticalSection(&g_lock);

    for (DWORD i = 0; i < ARRAYSIZE(g_pending) &&
                      completedCount < ARRAYSIZE(completed);
         i++) {
        if (!g_pending[i].inUse || !g_pending[i].overlapped) {
            continue;
        }

        ULONG_PTR status = g_pending[i].overlapped->Internal;
        ULONG_PTR bytes = g_pending[i].overlapped->InternalHigh;

        if (status == kStatusPending) {
            continue;
        }

        completed[completedCount].transfer = g_pending[i];
        completed[completedCount].bytesTransferred =
            ClampTransferLength(bytes, g_pending[i].requestedLength);
        completed[completedCount].ok =
            (static_cast<LONG>(status) >= 0) ? TRUE : FALSE;
        completed[completedCount].lastError =
            completed[completedCount].ok ? ERROR_SUCCESS
                                         : static_cast<DWORD>(status);
        completedCount++;
        g_pending[i].inUse = false;
    }

    LeaveCriticalSection(&g_lock);

    for (DWORD i = 0; i < completedCount; i++) {
        if (completed[i].bytesTransferred > 0) {
            EnqueuePendingTransfer(completed[i].transfer,
                                   completed[i].bytesTransferred,
                                   completed[i].ok,
                                   completed[i].lastError);
        }
    }

    SetLastError(savedLastError);
}

static BOOL WINAPI WinUsb_WritePipe_Hook(WINUSB_INTERFACE_HANDLE interfaceHandle,
                                         UCHAR pipeId,
                                         PUCHAR buffer,
                                         ULONG bufferLength,
                                         PULONG lengthTransferred,
                                         LPOVERLAPPED overlapped) {
    BOOL ok = WinUsb_WritePipe_Original(interfaceHandle, pipeId, buffer,
                                        bufferLength, lengthTransferred,
                                        overlapped);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();
    DWORD actualLength = lengthTransferred ? *lengthTransferred : bufferLength;

    EnqueueBuffer("WinUsb_WritePipe", L"WritePipe", "out", L"out", pipeId,
                  buffer, bufferLength, bufferLength, ok, lastError,
                  !ok && lastError == ERROR_IO_PENDING);

    if (ok && actualLength != bufferLength) {
        EnqueueBuffer("WinUsb_WritePipe", L"WritePipe", "out_result",
                      L"outres", pipeId, buffer, bufferLength, actualLength, ok,
                      lastError, false);
    }

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI WinUsb_ReadPipe_Hook(WINUSB_INTERFACE_HANDLE interfaceHandle,
                                        UCHAR pipeId,
                                        PUCHAR buffer,
                                        ULONG bufferLength,
                                        PULONG lengthTransferred,
                                        LPOVERLAPPED overlapped) {
    BOOL ok = WinUsb_ReadPipe_Original(interfaceHandle, pipeId, buffer,
                                       bufferLength, lengthTransferred,
                                       overlapped);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();
    DWORD actualLength = lengthTransferred ? *lengthTransferred : 0;

    if (ok && actualLength > 0) {
        EnqueueBuffer("WinUsb_ReadPipe", L"ReadPipe", "in", L"in", pipeId,
                      buffer, bufferLength, actualLength, ok, lastError, false);
    } else if (!ok && lastError == ERROR_IO_PENDING) {
        RememberPending(overlapped, buffer, bufferLength, pipeId,
                        "WinUsb_ReadPipe", L"ReadPipe", "in", L"in");
    }

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI WinUsb_ControlTransfer_Hook(
    WINUSB_INTERFACE_HANDLE interfaceHandle,
    WINUSB_SETUP_PACKET setupPacket,
    PUCHAR buffer,
    ULONG bufferLength,
    PULONG lengthTransferred,
    LPOVERLAPPED overlapped) {
    bool isIn = (setupPacket.RequestType & 0x80) != 0;

    if (!isIn && buffer && bufferLength > 0) {
        EnqueueBuffer("WinUsb_ControlTransfer", L"Control", "ctrl_out",
                      L"ctrlout", 0xff, buffer, bufferLength, bufferLength,
                      TRUE, ERROR_SUCCESS, false);
    }

    BOOL ok = WinUsb_ControlTransfer_Original(interfaceHandle, setupPacket,
                                              buffer, bufferLength,
                                              lengthTransferred, overlapped);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();
    DWORD actualLength = lengthTransferred ? *lengthTransferred : 0;

    if (isIn && ok && actualLength > 0) {
        EnqueueBuffer("WinUsb_ControlTransfer", L"Control", "ctrl_in",
                      L"ctrlin", 0xff, buffer, bufferLength, actualLength, ok,
                      lastError, false);
    } else if (isIn && !ok && lastError == ERROR_IO_PENDING) {
        RememberPending(overlapped, buffer, bufferLength, 0xff,
                        "WinUsb_ControlTransfer", L"Control", "ctrl_in",
                        L"ctrlin");
    }

    SetLastError(lastError);
    return ok;
}

static void EnqueueCompletedOverlapped(LPOVERLAPPED overlapped,
                                       LPDWORD numberOfBytesTransferred,
                                       BOOL ok,
                                       DWORD lastError) {
    if (!ok || !numberOfBytesTransferred || *numberOfBytesTransferred == 0) {
        return;
    }

    PendingTransfer transfer = {};
    if (TakePending(overlapped, &transfer)) {
        EnqueuePendingTransfer(transfer, *numberOfBytesTransferred, ok,
                               lastError);
    }
}

static void EnqueueCompletedEvent(HANDLE eventHandle, BOOL ok, DWORD lastError) {
    PendingTransfer transfer = {};
    if (!TakePendingByEvent(eventHandle, &transfer)) {
        return;
    }

    DWORD bytesTransferred = 0;
    if (transfer.overlapped) {
        bytesTransferred = static_cast<DWORD>(transfer.overlapped->InternalHigh);
    }

    EnqueuePendingTransfer(transfer, bytesTransferred, ok, lastError);
}

static BOOL WINAPI WinUsb_GetOverlappedResult_Hook(
    WINUSB_INTERFACE_HANDLE interfaceHandle,
    LPOVERLAPPED overlapped,
    LPDWORD numberOfBytesTransferred,
    BOOL wait) {
    BOOL ok = WinUsb_GetOverlappedResult_Original(interfaceHandle, overlapped,
                                                  numberOfBytesTransferred,
                                                  wait);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();

    EnqueueCompletedOverlapped(overlapped, numberOfBytesTransferred, ok,
                               lastError);

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI Kernel32_GetOverlappedResult_Hook(
    HANDLE file,
    LPOVERLAPPED overlapped,
    LPDWORD numberOfBytesTransferred,
    BOOL wait) {
    BOOL ok = Kernel32_GetOverlappedResult_Original(
        file, overlapped, numberOfBytesTransferred, wait);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();

    EnqueueCompletedOverlapped(overlapped, numberOfBytesTransferred, ok,
                               lastError);

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI KernelBase_GetOverlappedResult_Hook(
    HANDLE file,
    LPOVERLAPPED overlapped,
    LPDWORD numberOfBytesTransferred,
    BOOL wait) {
    BOOL ok = KernelBase_GetOverlappedResult_Original(
        file, overlapped, numberOfBytesTransferred, wait);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();

    EnqueueCompletedOverlapped(overlapped, numberOfBytesTransferred, ok,
                               lastError);

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI Kernel32_GetQueuedCompletionStatus_Hook(
    HANDLE completionPort,
    LPDWORD numberOfBytesTransferred,
    PULONG_PTR completionKey,
    LPOVERLAPPED* overlapped,
    DWORD milliseconds) {
    BOOL ok = Kernel32_GetQueuedCompletionStatus_Original(
        completionPort, numberOfBytesTransferred, completionKey, overlapped,
        milliseconds);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();

    if (overlapped && *overlapped) {
        EnqueueCompletedOverlapped(*overlapped, numberOfBytesTransferred, ok,
                                   lastError);
    }

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI KernelBase_GetQueuedCompletionStatus_Hook(
    HANDLE completionPort,
    LPDWORD numberOfBytesTransferred,
    PULONG_PTR completionKey,
    LPOVERLAPPED* overlapped,
    DWORD milliseconds) {
    BOOL ok = KernelBase_GetQueuedCompletionStatus_Original(
        completionPort, numberOfBytesTransferred, completionKey, overlapped,
        milliseconds);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();

    if (overlapped && *overlapped) {
        EnqueueCompletedOverlapped(*overlapped, numberOfBytesTransferred, ok,
                                   lastError);
    }

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI Kernel32_GetQueuedCompletionStatusEx_Hook(
    HANDLE completionPort,
    LPOVERLAPPED_ENTRY completionPortEntries,
    ULONG count,
    PULONG numEntriesRemoved,
    DWORD milliseconds,
    BOOL alertable) {
    BOOL ok = Kernel32_GetQueuedCompletionStatusEx_Original(
        completionPort, completionPortEntries, count, numEntriesRemoved,
        milliseconds, alertable);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();

    if (ok && completionPortEntries && numEntriesRemoved) {
        for (ULONG i = 0; i < *numEntriesRemoved; i++) {
            DWORD bytes = completionPortEntries[i].dwNumberOfBytesTransferred;
            LPOVERLAPPED overlapped = completionPortEntries[i].lpOverlapped;
            EnqueueCompletedOverlapped(overlapped, &bytes, ok, lastError);
        }
    }

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI KernelBase_GetQueuedCompletionStatusEx_Hook(
    HANDLE completionPort,
    LPOVERLAPPED_ENTRY completionPortEntries,
    ULONG count,
    PULONG numEntriesRemoved,
    DWORD milliseconds,
    BOOL alertable) {
    BOOL ok = KernelBase_GetQueuedCompletionStatusEx_Original(
        completionPort, completionPortEntries, count, numEntriesRemoved,
        milliseconds, alertable);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();

    if (ok && completionPortEntries && numEntriesRemoved) {
        for (ULONG i = 0; i < *numEntriesRemoved; i++) {
            DWORD bytes = completionPortEntries[i].dwNumberOfBytesTransferred;
            LPOVERLAPPED overlapped = completionPortEntries[i].lpOverlapped;
            EnqueueCompletedOverlapped(overlapped, &bytes, ok, lastError);
        }
    }

    SetLastError(lastError);
    return ok;
}

static DWORD WINAPI Kernel32_WaitForSingleObject_Hook(HANDLE handle,
                                                       DWORD milliseconds) {
    DWORD result = Kernel32_WaitForSingleObject_Original(handle, milliseconds);
    DWORD lastError = GetLastError();

    if (result == WAIT_OBJECT_0) {
        EnqueueCompletedEvent(handle, TRUE, ERROR_SUCCESS);
    }

    SetLastError(lastError);
    return result;
}

static DWORD WINAPI KernelBase_WaitForSingleObject_Hook(HANDLE handle,
                                                         DWORD milliseconds) {
    DWORD result = KernelBase_WaitForSingleObject_Original(handle, milliseconds);
    DWORD lastError = GetLastError();

    if (result == WAIT_OBJECT_0) {
        EnqueueCompletedEvent(handle, TRUE, ERROR_SUCCESS);
    }

    SetLastError(lastError);
    return result;
}

static DWORD WINAPI Kernel32_WaitForSingleObjectEx_Hook(HANDLE handle,
                                                         DWORD milliseconds,
                                                         BOOL alertable) {
    DWORD result =
        Kernel32_WaitForSingleObjectEx_Original(handle, milliseconds, alertable);
    DWORD lastError = GetLastError();

    if (result == WAIT_OBJECT_0) {
        EnqueueCompletedEvent(handle, TRUE, ERROR_SUCCESS);
    }

    SetLastError(lastError);
    return result;
}

static DWORD WINAPI KernelBase_WaitForSingleObjectEx_Hook(HANDLE handle,
                                                           DWORD milliseconds,
                                                           BOOL alertable) {
    DWORD result = KernelBase_WaitForSingleObjectEx_Original(
        handle, milliseconds, alertable);
    DWORD lastError = GetLastError();

    if (result == WAIT_OBJECT_0) {
        EnqueueCompletedEvent(handle, TRUE, ERROR_SUCCESS);
    }

    SetLastError(lastError);
    return result;
}

static void EnqueueCompletedWaitArrayResult(DWORD result,
                                            DWORD count,
                                            const HANDLE* handles,
                                            BOOL waitAll) {
    if (!handles || count == 0) {
        return;
    }

    if (waitAll && result == WAIT_OBJECT_0) {
        for (DWORD i = 0; i < count; i++) {
            EnqueueCompletedEvent(handles[i], TRUE, ERROR_SUCCESS);
        }
    } else if (!waitAll && result >= WAIT_OBJECT_0 &&
               result < WAIT_OBJECT_0 + count) {
        EnqueueCompletedEvent(handles[result - WAIT_OBJECT_0], TRUE,
                              ERROR_SUCCESS);
    }
}

static DWORD WINAPI Kernel32_WaitForMultipleObjects_Hook(
    DWORD count,
    const HANDLE* handles,
    BOOL waitAll,
    DWORD milliseconds) {
    DWORD result = Kernel32_WaitForMultipleObjects_Original(
        count, handles, waitAll, milliseconds);
    DWORD lastError = GetLastError();

    EnqueueCompletedWaitArrayResult(result, count, handles, waitAll);

    SetLastError(lastError);
    return result;
}

static DWORD WINAPI KernelBase_WaitForMultipleObjects_Hook(
    DWORD count,
    const HANDLE* handles,
    BOOL waitAll,
    DWORD milliseconds) {
    DWORD result = KernelBase_WaitForMultipleObjects_Original(
        count, handles, waitAll, milliseconds);
    DWORD lastError = GetLastError();

    EnqueueCompletedWaitArrayResult(result, count, handles, waitAll);

    SetLastError(lastError);
    return result;
}

static DWORD WINAPI Kernel32_WaitForMultipleObjectsEx_Hook(
    DWORD count,
    const HANDLE* handles,
    BOOL waitAll,
    DWORD milliseconds,
    BOOL alertable) {
    DWORD result = Kernel32_WaitForMultipleObjectsEx_Original(
        count, handles, waitAll, milliseconds, alertable);
    DWORD lastError = GetLastError();

    EnqueueCompletedWaitArrayResult(result, count, handles, waitAll);

    SetLastError(lastError);
    return result;
}

static DWORD WINAPI KernelBase_WaitForMultipleObjectsEx_Hook(
    DWORD count,
    const HANDLE* handles,
    BOOL waitAll,
    DWORD milliseconds,
    BOOL alertable) {
    DWORD result = KernelBase_WaitForMultipleObjectsEx_Original(
        count, handles, waitAll, milliseconds, alertable);
    DWORD lastError = GetLastError();

    EnqueueCompletedWaitArrayResult(result, count, handles, waitAll);

    SetLastError(lastError);
    return result;
}

static void EnqueueIoctlInput(const char* api,
                              const wchar_t* apiW,
                              DWORD ioctlCode,
                              const void* inputBuffer,
                              DWORD inputBufferLength) {
    ScanCompletedPendingTransfers();

    if (!inputBuffer || inputBufferLength == 0) {
        return;
    }

    EnqueueBufferWithIoctl(api, apiW, "ioctl_in", L"ioctlin", 0xfe,
                           ioctlCode, static_cast<const BYTE*>(inputBuffer),
                           inputBufferLength, inputBufferLength, TRUE,
                           ERROR_SUCCESS, false);
}

static void EnqueueIoctlOutput(const char* api,
                               const wchar_t* apiW,
                               DWORD ioctlCode,
                               const void* outputBuffer,
                               DWORD outputBufferLength,
                               DWORD actualLength,
                               BOOL ok,
                               DWORD lastError,
                               bool pending) {
    if (!outputBuffer || actualLength == 0) {
        return;
    }

    DWORD clampedLength = ClampTransferLength(actualLength, outputBufferLength);
    EnqueueBufferWithIoctl(api, apiW, "ioctl_out", L"ioctlout", 0xfd,
                           ioctlCode, static_cast<const BYTE*>(outputBuffer),
                           outputBufferLength, clampedLength, ok, lastError,
                           pending);
}

static void RememberIoctlOutput(LPOVERLAPPED overlapped,
                                HANDLE eventHandle,
                                DWORD ioctlCode,
                                void* outputBuffer,
                                DWORD outputBufferLength,
                                const char* api,
                                const wchar_t* apiW) {
    if (!outputBuffer || outputBufferLength == 0) {
        return;
    }

    RememberPendingEx(overlapped, eventHandle, static_cast<PUCHAR>(outputBuffer),
                      outputBufferLength, 0xfd, ioctlCode, api, apiW,
                      "ioctl_out", L"ioctlout");
}

static BOOL WINAPI Kernel32_DeviceIoControl_Hook(HANDLE device,
                                                 DWORD ioctlCode,
                                                 LPVOID inputBuffer,
                                                 DWORD inputBufferLength,
                                                 LPVOID outputBuffer,
                                                 DWORD outputBufferLength,
                                                 LPDWORD bytesReturned,
                                                 LPOVERLAPPED overlapped) {
    EnqueueIoctlInput("DeviceIoControl", L"DevIoctl", ioctlCode, inputBuffer,
                      inputBufferLength);

    BOOL ok = Kernel32_DeviceIoControl_Original(
        device, ioctlCode, inputBuffer, inputBufferLength, outputBuffer,
        outputBufferLength, bytesReturned, overlapped);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();
    DWORD actualLength = bytesReturned ? *bytesReturned : 0;

    if (ok && actualLength > 0) {
        EnqueueIoctlOutput("DeviceIoControl", L"DevIoctl", ioctlCode,
                           outputBuffer, outputBufferLength, actualLength, ok,
                           lastError, false);
    } else if (!ok && lastError == ERROR_IO_PENDING && overlapped) {
        RememberIoctlOutput(overlapped, overlapped->hEvent, ioctlCode,
                            outputBuffer, outputBufferLength,
                            "DeviceIoControl", L"DevIoctl");
    }

    SetLastError(lastError);
    return ok;
}

static BOOL WINAPI KernelBase_DeviceIoControl_Hook(HANDLE device,
                                                   DWORD ioctlCode,
                                                   LPVOID inputBuffer,
                                                   DWORD inputBufferLength,
                                                   LPVOID outputBuffer,
                                                   DWORD outputBufferLength,
                                                   LPDWORD bytesReturned,
                                                   LPOVERLAPPED overlapped) {
    EnqueueIoctlInput("DeviceIoControl", L"DevIoctl", ioctlCode, inputBuffer,
                      inputBufferLength);

    BOOL ok = KernelBase_DeviceIoControl_Original(
        device, ioctlCode, inputBuffer, inputBufferLength, outputBuffer,
        outputBufferLength, bytesReturned, overlapped);
    DWORD lastError = ok ? ERROR_SUCCESS : GetLastError();
    DWORD actualLength = bytesReturned ? *bytesReturned : 0;

    if (ok && actualLength > 0) {
        EnqueueIoctlOutput("DeviceIoControl", L"DevIoctl", ioctlCode,
                           outputBuffer, outputBufferLength, actualLength, ok,
                           lastError, false);
    } else if (!ok && lastError == ERROR_IO_PENDING && overlapped) {
        RememberIoctlOutput(overlapped, overlapped->hEvent, ioctlCode,
                            outputBuffer, outputBufferLength,
                            "DeviceIoControl", L"DevIoctl");
    }

    SetLastError(lastError);
    return ok;
}

static WH_NTSTATUS NTAPI Ntdll_NtDeviceIoControlFile_Hook(
    HANDLE file,
    HANDLE eventHandle,
    PVOID apcRoutine,
    PVOID apcContext,
    WH_IO_STATUS_BLOCK* ioStatusBlock,
    ULONG ioctlCode,
    PVOID inputBuffer,
    ULONG inputBufferLength,
    PVOID outputBuffer,
    ULONG outputBufferLength) {
    EnqueueIoctlInput("NtDeviceIoControlFile", L"NtDevIoctl", ioctlCode,
                      inputBuffer, inputBufferLength);

    WH_NTSTATUS status = Ntdll_NtDeviceIoControlFile_Original(
        file, eventHandle, apcRoutine, apcContext, ioStatusBlock, ioctlCode,
        inputBuffer, inputBufferLength, outputBuffer, outputBufferLength);
    DWORD lastError = GetLastError();

    if (status >= 0 && status != kStatusPending && ioStatusBlock) {
        DWORD actualLength =
            ClampTransferLength(ioStatusBlock->Information, outputBufferLength);
        EnqueueIoctlOutput("NtDeviceIoControlFile", L"NtDevIoctl", ioctlCode,
                           outputBuffer, outputBufferLength, actualLength, TRUE,
                           ERROR_SUCCESS, false);
    } else if (status == kStatusPending && ioStatusBlock) {
        RememberIoctlOutput(reinterpret_cast<LPOVERLAPPED>(ioStatusBlock),
                            eventHandle, ioctlCode, outputBuffer,
                            outputBufferLength, "NtDeviceIoControlFile",
                            L"NtDevIoctl");
    }

    SetLastError(lastError);
    return status;
}

static DWORD ClampReadableLength(const void* buffer,
                                 DWORD requestedLength,
                                 DWORD fallbackLength) {
    DWORD length = requestedLength ? requestedLength : fallbackLength;
    if (length > kMaxCaptureBytes) {
        length = kMaxCaptureBytes;
    }

    if (!length || !IsReadableRange(buffer, length)) {
        return 0;
    }

    return length;
}

static void CaptureWbdiCommandBuffer(const char* direction,
                                     const wchar_t* directionW,
                                     DWORD tag,
                                     const void* buffer,
                                     DWORD requestedLength,
                                     DWORD fallbackLength,
                                     BOOL ok,
                                     DWORD lastError) {
    DWORD length = ClampReadableLength(buffer, requestedLength, fallbackLength);
    if (!length) {
        return;
    }

    EnqueueBufferWithIoctl("WbdiIoHubExec", L"WbdiIoHub", direction,
                           directionW, 0xfb, tag,
                           static_cast<const BYTE*>(buffer), requestedLength,
                           length, ok, lastError, false);
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
        EnqueueBufferWithIoctl("WbdiPskGet", L"WbdiPskGet", "wbdi_psk",
                               L"wbdipsk", 0xfa, 0x50534b00,
                               static_cast<const BYTE*>(outputBuffer),
                               outputBufferLength, actualLength, TRUE,
                               ERROR_SUCCESS, false);
    }

    return result;
}

static LONG_PTR WINAPI WbdiIoHubExec_Hook(void* ioHub, void* command) {
    DWORD workType = ReadU32Field(command, 0x04);
    DWORD commandId = ReadU16Field(command, 0x08);
    DWORD tag = (workType << 16) | commandId;
    void* outBuffer = ReadPointerField(command, 0x10);
    DWORD outLength = ReadU32Field(command, 0x18);
    void* inBuffer = ReadPointerField(command, 0x20);
    DWORD inLength = ReadU32Field(command, 0x28);

    if (outBuffer && outLength) {
        CaptureWbdiCommandBuffer(workType == 5 ? "wbdi_tls_out"
                                               : "wbdi_cmd_out",
                                 workType == 5 ? L"wbditlsout"
                                               : L"wbdicmdout",
                                 tag, outBuffer, outLength, outLength, TRUE,
                                 ERROR_SUCCESS);
    }

    LONG_PTR result = WbdiIoHubExec_Original(ioHub, command);

    DWORD status = ReadU32Field(command, 0x60);
    if (inBuffer && inLength) {
        CaptureWbdiCommandBuffer(workType == 5 ? "wbdi_tls_in"
                                               : "wbdi_cmd_in",
                                 workType == 5 ? L"wbditlsin"
                                               : L"wbdicmdin",
                                 tag, inBuffer, inLength, inLength,
                                 result != 0 ? TRUE : FALSE, status);
    }

    return result;
}

static bool HookExport(HMODULE module,
                       const char* name,
                       void* hook,
                       void** original) {
    void* target = reinterpret_cast<void*>(GetProcAddress(module, name));
    if (!target) {
        Wh_Log(L"missing export: %S", name);
        return false;
    }

    if (!Wh_SetFunctionHook(target, hook, original)) {
        Wh_Log(L"failed to hook export: %S", name);
        return false;
    }

    Wh_Log(L"hooked export: %S", name);
    return true;
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

static void FreeQueuedItems() {
    CaptureItem* item = nullptr;
    while ((item = PopCapture()) != nullptr) {
        HeapFree(GetProcessHeap(), 0, item);
    }
}

BOOL Wh_ModInit() {
    InitializeCriticalSection(&g_lock);
    g_lockReady = true;
    g_queueEvent = CreateEventW(nullptr, FALSE, FALSE, nullptr);
    if (!g_queueEvent) {
        return FALSE;
    }

    InterlockedExchange(&g_workerStop, 0);
    InterlockedExchange(&g_acceptingCaptures, 1);
    g_workerThread = CreateThread(nullptr, 0, CaptureWorkerThread, nullptr, 0,
                                  nullptr);
    if (!g_workerThread) {
        InterlockedExchange(&g_acceptingCaptures, 0);
        CloseHandle(g_queueEvent);
        g_queueEvent = nullptr;
        DeleteCriticalSection(&g_lock);
        g_lockReady = false;
        return FALSE;
    }

    EnsureCaptureDirs();

    HMODULE winusb = GetModuleHandleW(L"WINUSB.DLL");
    if (!winusb) {
        winusb = LoadLibraryW(L"WINUSB.DLL");
    }
    if (!winusb) {
        Wh_Log(L"WINUSB.DLL is not available in this process");
        return FALSE;
    }

    bool ok = true;
    ok &= HookExport(winusb, "WinUsb_WritePipe",
                     reinterpret_cast<void*>(WinUsb_WritePipe_Hook),
                     reinterpret_cast<void**>(&WinUsb_WritePipe_Original));
    ok &= HookExport(winusb, "WinUsb_ReadPipe",
                     reinterpret_cast<void*>(WinUsb_ReadPipe_Hook),
                     reinterpret_cast<void**>(&WinUsb_ReadPipe_Original));
    ok &= HookExport(winusb, "WinUsb_ControlTransfer",
                     reinterpret_cast<void*>(WinUsb_ControlTransfer_Hook),
                     reinterpret_cast<void**>(&WinUsb_ControlTransfer_Original));
    ok &= HookExport(
        winusb, "WinUsb_GetOverlappedResult",
        reinterpret_cast<void*>(WinUsb_GetOverlappedResult_Hook),
        reinterpret_cast<void**>(&WinUsb_GetOverlappedResult_Original));

    HMODULE kernel32 = GetModuleHandleW(L"KERNEL32.DLL");
    if (kernel32) {
        HookExport(kernel32, "DeviceIoControl",
                   reinterpret_cast<void*>(Kernel32_DeviceIoControl_Hook),
                   reinterpret_cast<void**>(&Kernel32_DeviceIoControl_Original));
        HookExport(kernel32, "GetOverlappedResult",
                   reinterpret_cast<void*>(Kernel32_GetOverlappedResult_Hook),
                   reinterpret_cast<void**>(
                       &Kernel32_GetOverlappedResult_Original));
        HookExport(kernel32, "GetQueuedCompletionStatus",
                   reinterpret_cast<void*>(
                       Kernel32_GetQueuedCompletionStatus_Hook),
                   reinterpret_cast<void**>(
                       &Kernel32_GetQueuedCompletionStatus_Original));
        HookExport(kernel32, "GetQueuedCompletionStatusEx",
                   reinterpret_cast<void*>(
                       Kernel32_GetQueuedCompletionStatusEx_Hook),
                   reinterpret_cast<void**>(
                       &Kernel32_GetQueuedCompletionStatusEx_Original));
        HookExport(kernel32, "WaitForSingleObject",
                   reinterpret_cast<void*>(Kernel32_WaitForSingleObject_Hook),
                   reinterpret_cast<void**>(
                       &Kernel32_WaitForSingleObject_Original));
        HookExport(kernel32, "WaitForSingleObjectEx",
                   reinterpret_cast<void*>(Kernel32_WaitForSingleObjectEx_Hook),
                   reinterpret_cast<void**>(
                       &Kernel32_WaitForSingleObjectEx_Original));
        HookExport(kernel32, "WaitForMultipleObjects",
                   reinterpret_cast<void*>(Kernel32_WaitForMultipleObjects_Hook),
                   reinterpret_cast<void**>(
                       &Kernel32_WaitForMultipleObjects_Original));
        HookExport(
            kernel32, "WaitForMultipleObjectsEx",
            reinterpret_cast<void*>(Kernel32_WaitForMultipleObjectsEx_Hook),
            reinterpret_cast<void**>(&Kernel32_WaitForMultipleObjectsEx_Original));
    }

    HMODULE kernelBase = GetModuleHandleW(L"KERNELBASE.DLL");
    if (kernelBase) {
        HookExport(kernelBase, "DeviceIoControl",
                   reinterpret_cast<void*>(KernelBase_DeviceIoControl_Hook),
                   reinterpret_cast<void**>(
                       &KernelBase_DeviceIoControl_Original));
        HookExport(kernelBase, "GetOverlappedResult",
                   reinterpret_cast<void*>(KernelBase_GetOverlappedResult_Hook),
                   reinterpret_cast<void**>(
                       &KernelBase_GetOverlappedResult_Original));
        HookExport(kernelBase, "GetQueuedCompletionStatus",
                   reinterpret_cast<void*>(
                       KernelBase_GetQueuedCompletionStatus_Hook),
                   reinterpret_cast<void**>(
                       &KernelBase_GetQueuedCompletionStatus_Original));
        HookExport(kernelBase, "GetQueuedCompletionStatusEx",
                   reinterpret_cast<void*>(
                       KernelBase_GetQueuedCompletionStatusEx_Hook),
                   reinterpret_cast<void**>(
                       &KernelBase_GetQueuedCompletionStatusEx_Original));
        HookExport(kernelBase, "WaitForSingleObject",
                   reinterpret_cast<void*>(KernelBase_WaitForSingleObject_Hook),
                   reinterpret_cast<void**>(
                       &KernelBase_WaitForSingleObject_Original));
        HookExport(
            kernelBase, "WaitForSingleObjectEx",
            reinterpret_cast<void*>(KernelBase_WaitForSingleObjectEx_Hook),
            reinterpret_cast<void**>(&KernelBase_WaitForSingleObjectEx_Original));
        HookExport(
            kernelBase, "WaitForMultipleObjects",
            reinterpret_cast<void*>(KernelBase_WaitForMultipleObjects_Hook),
            reinterpret_cast<void**>(&KernelBase_WaitForMultipleObjects_Original));
        HookExport(kernelBase, "WaitForMultipleObjectsEx",
                   reinterpret_cast<void*>(
                       KernelBase_WaitForMultipleObjectsEx_Hook),
                   reinterpret_cast<void**>(
                       &KernelBase_WaitForMultipleObjectsEx_Original));
    }

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        HookExport(ntdll, "NtDeviceIoControlFile",
                   reinterpret_cast<void*>(Ntdll_NtDeviceIoControlFile_Hook),
                   reinterpret_cast<void**>(&Ntdll_NtDeviceIoControlFile_Original));
    }

    HMODULE wbdi = GetModuleHandleW(L"Wbdi.dll");
    if (!wbdi) {
        wbdi = GetModuleHandleW(L"WBDI.DLL");
    }
    if (wbdi) {
        ok &= HookInternal(wbdi, 0x78658, L"Wbdi!PresetPskPskGet",
                           reinterpret_cast<void*>(
                               WbdiPresetPskPskGet_Hook),
                           reinterpret_cast<void**>(
                               &WbdiPresetPskPskGet_Original));
        ok &= HookInternal(wbdi, 0x5c550, L"Wbdi!IoHubExec",
                           reinterpret_cast<void*>(WbdiIoHubExec_Hook),
                           reinterpret_cast<void**>(&WbdiIoHubExec_Original));
    } else {
        Wh_Log(L"Wbdi.dll is not loaded; internal WBDI hooks skipped");
    }

    Wh_Log(L"Goodix WinUSB dump active at %s", kRoot);
    return ok ? TRUE : FALSE;
}

void Wh_ModUninit() {
    InterlockedExchange(&g_acceptingCaptures, 0);
    InterlockedExchange(&g_workerStop, 1);

    if (g_queueEvent) {
        SetEvent(g_queueEvent);
    }

    if (g_workerThread) {
        WaitForSingleObject(g_workerThread, 5000);
        CloseHandle(g_workerThread);
        g_workerThread = nullptr;
    }

    FreeQueuedItems();

    if (g_queueEvent) {
        CloseHandle(g_queueEvent);
        g_queueEvent = nullptr;
    }

    if (g_lockReady) {
        g_lockReady = false;
        DeleteCriticalSection(&g_lock);
    }
}
