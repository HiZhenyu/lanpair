"""Signed message envelopes bound to a recipient, with replay protection.

Every signature covers sender, recipient, timestamp, sequence number and body, so a
message meant for one device cannot be redirected to another, and a recorded message
cannot be played back later.
"""

from __future__ import annotations

import base64
import json
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .identity import Identity, PublicIdentity

VERSION = 1
DEFAULT_MAX_SKEW = 30.0  # seconds


class EnvelopeError(Exception):
    """Raised when an incoming envelope must be rejected."""


def _canonical(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _signed_fields(sender: str, recipient: str, ts: float, seq: int, body: Any) -> dict[str, Any]:
    return {"v": VERSION, "from": sender, "to": recipient, "ts": ts, "seq": seq, "body": body}


@dataclass
class Sealer:
    """Signs outgoing messages. Keep one per (identity, recipient) or share one; seq is global."""

    identity: Identity
    clock: Callable[[], float] = time.time
    _seq: int = 0

    def seal(self, recipient: PublicIdentity, body: Any) -> bytes:
        self._seq += 1
        fields = _signed_fields(
            self.identity.public.device_id, recipient.device_id, self.clock(), self._seq, body
        )
        sig = self.identity.sign(_canonical(fields))
        return _canonical({**fields, "sig": base64.b64encode(sig).decode()})


@dataclass
class Opener:
    """Verifies incoming messages for one local identity against paired peers."""

    me: PublicIdentity
    peers: dict[str, PublicIdentity] = field(default_factory=dict)
    clock: Callable[[], float] = time.time
    max_skew: float = DEFAULT_MAX_SKEW
    _last_seq: dict[str, int] = field(default_factory=dict)

    def add_peer(self, peer: PublicIdentity) -> None:
        self.peers[peer.device_id] = peer

    def remove_peer(self, device_id: str) -> None:
        self.peers.pop(device_id, None)
        self._last_seq.pop(device_id, None)

    def open(self, raw: bytes) -> tuple[PublicIdentity, Any]:
        try:
            msg = json.loads(raw)
            sig = base64.b64decode(msg.pop("sig"), validate=True)
            fields = _signed_fields(msg["from"], msg["to"], msg["ts"], msg["seq"], msg["body"])
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise EnvelopeError("malformed envelope") from e
        if msg.get("v") != VERSION or set(msg) != set(fields):
            raise EnvelopeError("unsupported envelope")

        peer = self.peers.get(fields["from"])
        if peer is None:
            raise EnvelopeError("unknown sender")
        if not peer.verify(_canonical(fields), sig):
            raise EnvelopeError("bad signature")
        if fields["to"] != self.me.device_id:
            raise EnvelopeError("not addressed to this device")
        if not isinstance(fields["seq"], int) or not isinstance(fields["ts"], (int, float)):
            raise EnvelopeError("malformed envelope")
        if abs(self.clock() - fields["ts"]) > self.max_skew:
            raise EnvelopeError("stale or future timestamp")
        if fields["seq"] <= self._last_seq.get(peer.device_id, 0):
            raise EnvelopeError("replayed message")

        self._last_seq[peer.device_id] = fields["seq"]
        return peer, fields["body"]
