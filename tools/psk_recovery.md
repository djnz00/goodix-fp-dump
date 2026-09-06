# Offline PSK recovery for the Goodix 52xd / 521d

The TLS pre-shared key can be recovered on Linux with no Windows boot, no
process injection and no Windhawk.

---

## Why this device needs it

The 521d arrives Windows-provisioned with a **random** 32-byte PSK, and
`preset_psk_write` (`0xe0`) is refused under stock `APP_10034`, so it cannot
be replaced with a known one. A random key with no write path is the whole
reason this exercise exists.

---

## Where the key actually lives

At provisioning, Windows generates a random 32-byte PSK, seals it with
`CryptProtectData`, and writes the sealed blob **into device flash** through
command `0xe0` as TLV `0xbb010002`. The device is storage only; it cannot read
what it holds. It exposes just `SHA-256(PSK)` through `0xbb020001` for
validation.

Every session, Windows reads the blob back and unseals it. That is why the PSK
exists only at runtime host-side, and why searching host storage for it finds
nothing.

**It is a two-part secret: the device holds the ciphertext, the Windows install
holds the key.** Neither is sufficient alone.

---

## The chain

```
device flash                     Windows volume
  TLV 0xbb010002                   SYSTEM hive
  324-byte DPAPI blob                └─ boot key (SYSKEY)
         │                                 └─ SECURITY hive → DPAPI_SYSTEM
         │                                       └─ master key 21970384-…
         │                                             │
         └─────────────── DPAPI decrypt ───────────────┘
                               │
                         32-byte PSK
                               │
                   sha256 == device 0xbb020001   ← the oracle, read live
```

`tools/psk.py` runs the whole chain in memory: it reads the sealed blob
(command `0xe4`, selector `0xbb010002`, length 324; the request must be the
16-byte form `goodix.py` emits when both `length` and `offset` are given:
the 8-byte `{selector, 0}` shape reads as a firmware refusal when it is
really a malformed request), walks the DPAPI chain against `--mount`, hashes
the result, compares against a fresh live `0xbb020001` device readback, and
only then writes `--out`. There is no hardcoded hash anywhere: the device is
the verification oracle on every run, so the tool works on any 521d.

| Stage | Bytes | How it is protected |
|---|---|---|
| Boot key (SYSKEY) | 16 | Not stored. Assembled from the `ClassName` of `Lsa\{JD,Skew1,GBG,Data}` in the `SYSTEM` hive, then permuted by a fixed table. Obfuscation, not encryption. |
| `DPAPI_SYSTEM` | 40 | LSA secret at `SECURITY\Policy\Secrets\DPAPI_SYSTEM`, encrypted under a key derived from the boot key. Splits into 20-byte machine and user halves. |
| Master key | 64 | `PBKDF2-HMAC-SHA1(dpapi_userkey, salt, iterations)` with salt and iteration count from the file header. Self-verifying: carries an HMAC, so a wrong key returns nothing rather than garbage. |
| The blob | 324 → 32 | Session key from `HMAC(master key, blob salt)`, expanded to AES key + IV. HMAC-verified payload. |

Blobs under `S-1-5-18/User/` take the **user** half; those directly under
`S-1-5-18/` take the machine half. The tool tries the half the path implies
first and falls back, which is safe precisely because a wrong key is detected.

`GfUnsealData:0246 >> The decryption phase worked, 324, 32` in the vendor's own
log is this exact operation. It is plain DPAPI despite the surrounding code
calling it `sgx`, and 324 bytes is far below the ≥560-byte minimum for real
enclave sealing.

---

## Why it works offline: no password is involved

User-context DPAPI binds to the user's password, so offline recovery needs that
password or a domain backup key.

**SYSTEM-context DPAPI has no password to bind to.** SYSTEM is not a person and
never types anything, so the root of trust is machine state only: two registry
hives sitting unencrypted on the disk.

This is not a flaw in Goodix's design and not a break of anything. It is how
Windows machine-scoped secrets are specified to work: **physical possession of
the disk is the credential.**

---

## Verification

| Check | Result |
|---|---|
| **Provenance.** Is the blob on the host? | Absent from host storage. It comes off the device. |
| **Negative control.** Flip one ciphertext byte | Decrypt fails. DPAPI HMAC-verifies the payload, so a spurious success is unreachable. |
| **Reproducibility.** Fresh device read, re-unseal | 32 bytes, hash match. |
| **Agreement** | `sha256(recovered) == device 0xbb020001` readback, checked live by the tool itself every run. |

Not circular: sealed blob from the device, master key from the host volume,
expected hash an independently read device value.

---

## Scope warning

Step 2 recovers `DPAPI_SYSTEM`, which unseals **every** SYSTEM-protected blob on
that install, not only the fingerprint credential. On one machine that was 62
blobs; we opened one. That reach is far wider than hooking a single API for a
single PSK, and it remains the strongest argument against using this route even
though it works.

This route was previously dropped on policy grounds for exactly that reason.
Nothing here overturns that decision; it only removes "impossible" as an
argument against it.

---

## Will it work elsewhere

**Yes**: another 521d on the same machine (each device carries its own blob);
another Windows install with its own sensor, since nothing here is
machine-specific and the blob format is stable across Windows versions.

**No**:

- **BitLocker.** The chain needs `SYSTEM` and `SECURITY` read offline. Modern
  laptops shipping Hello usually have device encryption on by default, and a
  fingerprint reader implies a modern laptop. This is the most likely blocker in
  practice.
- **Moving the sensor.** The master key does not travel. In another machine the
  device's blob is permanently undecryptable unless reprovisioned.
- **Wiped or reinstalled Windows.** Same reason: the blob outlives the key
  chain that opens it.
- **TPM-backed storage.** If a system sealed the credential through the Platform
  Crypto Provider rather than DPAPI this does not reach it.

So it is narrow: **one device family, Windows-provisioned, on an unencrypted
volume you still possess.** For a 521d owner with an intact dual-boot it works
and beats Windhawk. For a Linux-only user it does nothing, though neither does
Windhawk, which needs Windows running.

---

## The unlock that would actually generalise

Making `0xe0` writes work under stock `APP_10034`, so a Linux user could
provision their own PSK. The docs record that as hardware-refused.

Given that the `0xe4` read was also recorded as hardware-refused and turned out
to be a request-shape error, **the `0xe0` refusal deserves the same scrutiny
before it is trusted.** That is the highest-value open question on this path.

---

## Reproduce

```sh
uv run tools/psk.py --out /tmp/psk.bin --mount /path/to/windows-root
```

One command. `--out` and `--mount` are both required; there are no defaults
and no hardcoded hashes. The sealed blob and the PSK live in memory only;
`--out` is written `0600` only after `sha256(PSK)` matches the live device
readback. The PSK value never crosses a terminal, a log or a transcript:
output is sizes, paths and the hash-verification verdict.

For the libfprint driver, install it where the C driver reads it:

```sh
sudo install -m 600 -o root -g root /tmp/psk.bin \
  /var/lib/fprint/goodixtls52xd-27c6-521d.psk
shred -u /tmp/psk.bin
```
