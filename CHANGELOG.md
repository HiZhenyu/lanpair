# Changelog

## Unreleased

- First version: device identity and signed, recipient-bound, replay-protected envelopes.
- Message bodies are encrypted to the recipient (X25519, ChaCha20-Poly1305). Envelope
  version 2; `Opener` now takes the local `Identity`, and `PublicIdentity` carries an
  encryption key (`to_bytes` / `from_bytes`).
