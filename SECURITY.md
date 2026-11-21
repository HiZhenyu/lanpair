# Security

**Looking for security holes in lanpair is welcome.** It exists to keep forged and replayed
messages out of other people's projects, so a hole here matters. Reports are answered, fixed
and credited.

## Reporting a problem

**Please do not open a public issue for a security problem.** Report it privately instead:

- on GitHub, open the repository's **Security** tab and choose **Report a vulnerability**, or
- if that is not available, write to the maintainer through the contact on
  [TonyD365's GitHub profile](https://github.com/TonyD365).

Say what the problem is, how to reproduce it (a short script is ideal), and which version you
used. You will get an answer within a week. Please give a reasonable time to fix it before
telling anyone else.

## What happens after you report

1. You get an answer within a week, saying whether it is a vulnerability and how serious it is.
2. The fix is made in a private fork of the repository, where you are welcome to check it.
3. It is released on PyPI.
4. A security advisory is published here, with a CVE number when it is serious, and **you are
   credited in it** (unless you would rather not be).

Please keep it private until the advisory is out.

## What is in scope

The latest release on PyPI and the `main` branch. Before 1.0 only the latest release is fixed.

The threat model is in [docs/design.md](docs/design.md): an attacker on the same network who can
read, inject, replay and drop traffic and advertise fake devices, but cannot see the devices'
screens during pairing. Especially welcome:

- a way to get a message accepted that the paired peer did not send, or that was meant for
  another device, or that was already accepted once;
- a way to pair without seeing the QR code or the short code;
- key material showing up anywhere outside the OS key store.

## Known limits

- **No forward secrecy for the receiver**: bodies are encrypted with a fresh sender key, but
  someone who later steals a receiver's seed can decrypt messages they recorded earlier.
  Message sizes and who talks to whom stay visible on the network.
- **Pairing offers can be locked by guessing**: anyone on the network can send five wrong
  answers and lock an open offer (they cannot pair or learn the secret). Make a new offer.
- **Addresses follow authenticated messages**: an attacker who can delay a device's packet
  and deliver a copy from another address first makes the host reply to that address. The
  replies stay unreadable and unusable there; the next real message moves the address back.
- **No external security review yet.**
