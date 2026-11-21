# lanpair design

## Goal

Two devices on the same LAN find each other, establish trust once with a human in the
loop, and then exchange messages that the receiver can prove came from the paired peer,
were meant for it, and are not replays.

## Threat model

- Attacker is on the same LAN: can read, inject, drop, delay and replay packets, and can
  advertise fake mDNS services.
- Attacker does **not** see the device screens during pairing.
- Out of scope (v1): a compromised host, physical access to stored keys.

## Layers

1. **Discovery (mDNS / zeroconf).** Only finds addresses. Never a source of trust.
2. **Identity.** Each device generates an Ed25519 key pair on first run. The private key
   goes to the OS key store (Keychain / Windows Credential Manager / Secret Service via
   `keyring`); it is never written to a plain file.
3. **Pairing (once).**
   - *QR code:* carries the host's full public key, address and a 128-bit one-time secret.
     Scanning it is the out-of-band trust step.
   - *6-digit code:* too short to carry a key, so it must not be used as a plain shared
     check — a LAN attacker could swap public keys in transit. Use a PAKE (SPAKE2 or
     CPace) keyed by the code, and confirm both public keys inside the PAKE transcript.
     Limit attempts and expire the code.
   - Both sides show a short fingerprint of the peer key for an optional visual check.
4. **Messaging.** Every message is a signed envelope (`envelope.py`): the signature
   covers version, sender id, recipient id, timestamp, sequence number and body.
   Receivers drop anything with an unknown sender, bad signature, wrong recipient,
   timestamp outside ±30 s, or non-increasing sequence number. Rejected messages never
   reach application code.
   - *Restarts.* Sender sequence numbers start at the current time in microseconds, so
     they keep increasing across restarts with nothing stored. The receiver keeps the last
     accepted number per peer in a `SeqStore`: `JsonFileSeqStore` survives restarts; with
     the default in-memory store the receiver refuses anything stamped earlier than
     30 s after it started, so messages recorded before a restart cannot be replayed.
5. **Confidentiality.** Each identity also has an X25519 key, derived from the same seed
   with HKDF. Every body is encrypted to the recipient's X25519 key with a fresh
   ephemeral key (HKDF-SHA256, ChaCha20-Poly1305); the header is the AEAD associated data
   and the signature covers the ciphertext. Envelope version 2. Limit: no forward secrecy
   against a later theft of the receiver's seed; a Noise session could add it later.

## Open questions

- Mobile clients: a small web page or app speaking the same protocol.
- External security review before 1.0.

## Status

| Piece | State |
|---|---|
| Identity + signed envelopes | done, tested |
| Replay protection across restarts | done, tested |
| Key storage via OS key store | done, tested (`lanpair[keyring]`) |
| mDNS discovery | todo (port from YTKTV) |
| QR pairing | todo |
| PAKE code pairing | todo |
| Encrypted message bodies | done, tested |
| `Host` / `Device` high-level API | todo |
