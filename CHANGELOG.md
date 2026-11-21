# Changelog

## Unreleased

- `lanpair.discovery`: `Announcer` tells the LAN where a device listens, and
  `browse()` / `find(device_id)` locate devices with mDNS / DNS-SD. Announcements are
  validated and treated as untrusted hints. Optional: `pip install "lanpair[discovery]"`.

## 0.1.0 (2026-11-21)

First release: the cryptographic core. Discovery, pairing and the high-level `Host` /
`Device` API come in later releases.

- `Identity`: one 32-byte seed per device gives an Ed25519 signing key and an X25519
  encryption key. `PublicIdentity` is 64 bytes (`to_bytes` / `from_bytes`).
- `Sealer` / `Opener`: envelopes that are encrypted to the recipient (X25519,
  HKDF-SHA256, ChaCha20-Poly1305), signed by the sender, bound to the recipient, and
  rejected when stale (±30 s) or replayed.
- Replay protection survives restarts: time-based sender sequence numbers, and
  `JsonFileSeqStore` (or a start-up window with `MemorySeqStore`) on the receiver.
- Strict validation: malformed input of any kind raises `EnvelopeError`.
