# Cryptman

Cryptman is the zero-nonsense file encryption companion for people who expect modern cryptography by default. It pairs Argon2id key derivation with battle-tested authenticated ciphers so you can lock down archives, backups, and ad-hoc payloads without sacrificing control.

## Why Cryptman
- **Argon2id everywhere** – Stretch human passwords into high-entropy keys with the PHC winner, not yesterday’s PBKDF2.
- **Authenticated encryption** – Choose between `aes-256-gcm` and `xchacha20poly1305` for tamper-evident, constant-time protection.
- **Tunable hardening** – Dial in Argon2id time, memory, and parallelism to match laptop, workstation, or HSM profiles.
- **Streaming core** – Encrypt multi-gigabyte files in constant memory with chunked I/O and secure buffers.
- **CLI-first ergonomics** – Plain, scriptable commands with confirmation prompts and clear error messaging.

## Quick Start
```bash
# Build the binary
cargo build --release

# Encrypt a file (prompts for password)
./target/release/cryptman enc secrets.tar.zst secrets.tar.zst.enc

# Decrypt with matching cipher and KDF settings
./target/release/cryptman dec secrets.tar.zst.enc secrets.tar.zst
```

## KDF Controls
Argon2id parameters default to hardened presets, yet you remain in charge. Pass the CLI flags to raise time cost for longer derivations, bump memory cost for brute-force resistance, or increase parallelism when running on powerful gear. Whatever the profile, Cryptman validates every combination so unsafe settings never slip through.

## Built for Security Teams
Under the hood you’ll find secure memory handling, random nonces, and comprehensive error signaling—all reviewed with operational realities in mind. Whether you are seeding incident response kits or automating vault exports, Cryptman gives you a lean binary that takes modern cryptography seriously.

## Try It
Ready to ditch guesswork? Point Cryptman at your payloads, turn the KDF knobs to match your threat model, and ship encrypted artifacts with confidence.
