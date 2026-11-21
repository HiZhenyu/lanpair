# lanpair

[![CI](https://github.com/TonyD365/lanpair/actions/workflows/ci.yml/badge.svg)](https://github.com/TonyD365/lanpair/actions/workflows/ci.yml)
[![Security](https://github.com/TonyD365/lanpair/actions/workflows/security.yml/badge.svg)](https://github.com/TonyD365/lanpair/actions/workflows/security.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Secure pairing and signed messaging between devices on the same LAN.

> Status: early development. Not ready for production use.

## What it does

Lets two devices on the same Wi-Fi find each other, pair once with a QR code or a
short code, and then send messages that are signed, bound to the recipient and
protected against replay. Anything that fails verification is dropped before your
code sees it.

## Planned API

```python
# Host (e.g. a front desk)
from lanpair import Host

host = Host("Desk")
print(host.pairing_qr())
host.send("room-3", {"type": "close"})
for peer, msg in host.messages():  # already verified
    print(peer, msg)

# Device (e.g. a room PC)
from lanpair import Device

dev = Device("Room 3")
dev.pair(scanned_code)  # once
for msg in dev.messages():
    ...
```

## Available today

The low-level building blocks: `Identity` (Ed25519 keys) and `Sealer` / `Opener`
(signed, recipient-bound, replay-protected envelopes). See [docs/design.md](docs/design.md)
for the threat model and roadmap.

## Development

```bash
pip install -e ".[dev]"
pytest
```
