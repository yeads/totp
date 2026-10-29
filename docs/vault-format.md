# TOTP vault format, version 1

All integers use network byte order (big endian). The format is deliberately small and bounded; it does not serialize C structs or rely on native padding.

## File layout

| Offset | Size | Value |
| --- | --- | --- |
| 0 | 8 | ASCII magic `DOSOTP01` |
| 8 | 4 | PBKDF2 iteration count, exactly 600000 in version 1 |
| 12 | 16 | Random PBKDF2 salt |
| 28 | 12 | Random AES-GCM nonce, newly generated for each save |
| 40 | 4 | Ciphertext length in bytes |
| 44 | variable | AES-256-GCM ciphertext |
| 44 + ciphertext length | 16 | GCM authentication tag |

The 44-byte header is authenticated as GCM additional authenticated data. The key is 32 bytes derived using PBKDF2-HMAC-SHA256 from the password bytes and salt. Passwords are UTF-8 bytes as entered; no Unicode normalization is applied. Readers reject unknown versions, unexpected iteration counts, inconsistent lengths, trailing bytes and authentication failures. No account data is parsed until GCM authentication succeeds.

The salt is stable across ordinary saves because the unlocked session retains the derived key. A password change generates a new salt and key and re-encrypts the vault. The password itself is not retained after unlocking.

## Plaintext payload

The payload starts with a 4-byte account count (0–256), followed by that many account records:

| Field | Encoding |
| --- | --- |
| Issuer | 2-byte byte length, followed by up to 95 UTF-8 bytes |
| Account label | 2-byte byte length, followed by 1–95 UTF-8 bytes |
| Secret | 2-byte byte length, followed by Base32 text, at most 208 bytes |
| Hash | 1 byte: 1 = SHA1, 2 = SHA256, 3 = SHA512 |
| Digits | 1 byte: 6 or 8 |
| Period | 4-byte unsigned integer: 1–300 seconds |

Strings do not include a terminating NUL. Embedded NULs, ASCII control characters and colons in metadata are rejected; colons are reserved as separators in provisioning URI labels. Base32 is case insensitive; whitespace and hyphens are permitted for manual entry. Decoding must produce at most 128 bytes. Padding, if present, and unused trailing bits must be valid.

## Commit behavior

Writers hold a POSIX advisory write lock on the adjacent `<path>.lock` file for the entire session. The lock file is not removed at exit, avoiding a race between lock-file inodes. Readers in this application also acquire this lock because every session can modify the vault.

A save uses `mkstemp` in the same directory, sets mode `0600`, writes only encrypted bytes, calls `fsync`, closes the temporary file and commits with `rename`. A directory `fsync` is attempted after the rename; filesystems that reject directory synchronization may provide weaker power-loss durability. Before a successful rename, failures remove the temporary file and leave the original unchanged. The UI only replaces its in-memory account list after successful persistence.

Vault and lock files are opened with `O_NOFOLLOW`, and non-regular files are rejected. Advisory locks coordinate cooperating instances of this application; they do not prevent unrelated programs from changing the files. Backups should include the `.vault` file, not the `.lock` file.

See the [OpenSSL EVP encryption documentation](https://docs.openssl.org/3.0/man3/EVP_EncryptInit/) for the authenticated encryption API used by the implementation.
