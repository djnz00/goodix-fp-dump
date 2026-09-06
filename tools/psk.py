#!/usr/bin/env python3
"""Recover the 521d TLS PSK: device blob -> DPAPI unseal -> hash verify -> file.

Read-only toward the device (0xe4 does read only). Sealed blob and
recovered PSK stay in memory; --out is written 0600 only after sha256(PSK)
matches the live device hash readback. The PSK is never printed.

Full chain and scope warnings: tools/psk_recovery.md.
"""
import argparse
import glob
import hashlib
import os
import re
import shutil
import stat
import sys
import tempfile
import uuid
from binascii import unhexlify

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import driver_52xd

from impacket.dpapi import DPAPI_BLOB, MasterKey, MasterKeyFile
from impacket.examples.secretsdump import LocalOperations, LSASecrets

# Fixed provider GUID that marks the start of any DPAPI blob.
PROVIDER_GUID = unhexlify('d08c9ddf0115d1118c7a00c04fc297eb')

# Mount-relative. Which root holds a key depends on the service account that
# sealed the blob: LocalSystem in System32, LocalService/NetworkService under
# ServiceProfiles (S-1-5-19/-20).
MASTER_KEY_ROOTS = (
    'Windows/System32/Microsoft/Protect',
    'Windows/System32/config/systemprofile/AppData/Roaming/Microsoft/Protect',
    'Windows/ServiceProfiles/*/AppData/Roaming/Microsoft/Protect',
)

SEALED_SEL = 0xbb010002   # the sealed PSK TLV itself
SEALED_LEN = 324          # GfUnsealData:0246 logs "324, 32" on this unit
HASH_SEL = 0xbb020001     # SHA-256(PSK), the device-side verification oracle
HASH_LEN = 32
PSK_LEN = 32


def device_read(device, selector, length):
    """One preset_psk_read; -> (payload, error). Never prints payload."""
    try:
        reply = device.preset_psk_read(selector, length, 0)
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"
    if not reply or not reply[0]:
        return None, "MCU negative (device declined this selector/length)"
    if len(reply) < 3 or not reply[2]:
        return None, f"empty payload, flags={reply[1]:#x}" if len(reply) > 1 else "empty payload"
    return reply[2], None


def find_master_key(mount, guid):
    """Master key file for `guid`, at either <SID>/<guid> or <SID>/User/<guid>.

    Returns the path, not the bytes: unseal_master_key reads `/User/` out of it.
    Case-insensitive because NTFS preserves case and glob does not fold it."""
    for root in MASTER_KEY_ROOTS:
        for depth in ('*/*', '*/*/*'):
            for path in sorted(glob.glob(os.path.join(mount, root, depth))):
                if os.path.basename(path).lower() == guid and os.path.isfile(path):
                    return path
    assert False, f"master key {guid} not found in any of {[os.path.join(mount, r) for r in MASTER_KEY_ROOTS]}"


def find_hive(system32, name):
    """NTFS mounts differ on case; Windows itself does not care."""
    for variant in (name, name.lower(), name.upper()):
        path = os.path.join(system32, 'config', variant)
        if os.path.exists(path):
            return path
    assert False, f"{name} hive not found under {system32}/config"


def stage(path, tmpdir):
    """impacket opens hives 'r+b' and a mounted volume is root-owned, so copy
    to scratch rather than demanding root against the caller's own disk.
    copyfile, not copy: copy carries the source mode over, and a mount with a
    restrictive fmask would hand impacket a scratch file it cannot reopen."""
    return shutil.copyfile(path, os.path.join(tmpdir, os.path.basename(path)))


def read_dpapi_system(system_hive, security_hive):
    """-> (machine_key, user_key), via the boot key and without going through
    secretsdump's printing path."""
    boot_key = LocalOperations(system_hive).getBootKey()
    found = {}

    def on_secret(_secret_type, text):
        m = re.search(r'dpapi_machinekey:0x([0-9a-f]+)\s+dpapi_userkey:0x([0-9a-f]+)',
                      text, re.I)
        if m:
            found['machine'] = unhexlify(m.group(1))
            found['user'] = unhexlify(m.group(2))

    lsa = LSASecrets(security_hive, boot_key, None,
                     isRemote=False, perSecretCallback=on_secret)
    lsa.dumpSecrets()
    lsa.finish()
    assert 'user' in found
    return found['machine'], found['user']


def unseal_master_key(path, machine_key, user_key):
    """Keys under <SID>/User/ take the user half of DPAPI_SYSTEM, those directly
    under <SID>/ the machine half. Try what the path implies, then the other:
    MasterKey.decrypt HMAC-checks and returns None on a wrong key, so a bad
    guess is detected rather than silently yielding garbage."""
    raw = open(path, 'rb').read()
    mkf = MasterKeyFile(raw)
    body = raw[len(mkf):]
    mk = MasterKey(body[:mkf['MasterKeyLen']])

    is_user_store = f'{os.sep}User{os.sep}' in path
    for key in ([user_key, machine_key] if is_user_store else [machine_key, user_key]):
        decrypted = mk.decrypt(key)
        if decrypted:
            return decrypted
    assert False


def write_psk(path, psk):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as fh:
        fh.write(psk)
    try:
        mode = stat.S_IMODE(os.stat(path).st_mode)
        if mode & 0o077:
            os.chmod(path, 0o600)
    except OSError:
        pass
    print(f"wrote {path} (0600)")


def main():
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument('--out', required=True,
                    help='PSK destination, written 0600 only on hash match')
    ap.add_argument('--mount', required=True, help='mounted Windows root')
    ap.add_argument('--product', default='0x521d')
    args = ap.parse_args()

    device = driver_52xd.init_device(int(args.product, 0), strict_read_only=True)
    try:
        sealed, err = device_read(device, SEALED_SEL, SEALED_LEN)
        assert not err and sealed
        print(f"sealed blob: {len(sealed)} B from {SEALED_SEL:#x}")
    finally:
        try:
            device.disconnect()
        except Exception:
            pass

    start = sealed.find(PROVIDER_GUID)
    assert start >= 4
    start -= 4
    blob = DPAPI_BLOB(sealed[start:])

    # A Windows GUID stores its first three fields little-endian, so raw bytes
    # 84 03 97 21 are GUID 21970384. bytes_le= applies that; plain str() does
    # not, and yields a path that cannot exist.
    guid = str(uuid.UUID(bytes_le=bytes(blob['GuidMasterKey']))).lower()
    mk_path = find_master_key(args.mount, guid)
    print(f"master key: {os.path.relpath(mk_path, args.mount)}")

    system32 = os.path.join(args.mount, 'Windows', 'System32')
    system_hive = find_hive(system32, 'SYSTEM')
    security_hive = find_hive(system32, 'SECURITY')

    tmpdir = tempfile.mkdtemp(prefix='dpapi-hives-')
    try:
        machine_key, user_key = read_dpapi_system(stage(system_hive, tmpdir),
                                                  stage(security_hive, tmpdir))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    master_key = unseal_master_key(mk_path, machine_key, user_key)

    plain = blob.decrypt(master_key)
    assert plain is not None

    assert len(plain) == PSK_LEN
    recovered_hash = hashlib.sha256(plain).digest()

    device = driver_52xd.init_device(int(args.product, 0), strict_read_only=True)
    try:
        device_hash, err = device_read(device, HASH_SEL, HASH_LEN)
        assert not err and device_hash
    finally:
        try:
            device.disconnect()
        except Exception:
            pass

    assert len(device_hash) == HASH_LEN
    assert recovered_hash == device_hash
    print(f"hash verified: sha256(PSK) == device {HASH_SEL:#x} readback")

    # 4. Write only after verification.
    write_psk(args.out, plain)


if __name__ == '__main__':
    main()
