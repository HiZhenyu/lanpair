"""Signed message envelopes bound to a recipient, with replay protection.

Every signature covers sender, recipient, timestamp, sequence number and body, so a
message meant for one device cannot be redirected to another, and a recorded message
cannot be played back later, also not after either side restarts:

- The sender's sequence numbers start from the current time in microseconds, so they
  keep increasing across restarts without the sender storing anything.
- The receiver keeps the last sequence number it accepted from each peer in a
  ``SeqStore``. With a persistent store (``JsonFileSeqStore``) nothing recorded before a
  restart can be replayed after it. With the default in-memory store, the receiver
  instead refuses every message stamped earlier than ``max_skew`` after it started, so
  nothing sent before the restart is accepted again; that costs one ``max_skew`` window
  of messages after each start.
"""

from __future__ import annotations

import base64
import json
import math
import os
import tempfile
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from .identity import Identity, PublicIdentity

VERSION = 1
DEFAULT_MAX_SKEW = 30.0  # seconds


class EnvelopeError(Exception):
    """Raised when an incoming envelope must be rejected."""


class SeqStore(Protocol):
    """Where a receiver keeps the last accepted sequence number per peer."""

    persistent: bool

    def get(self, device_id: str) -> int: ...
    def set(self, device_id: str, seq: int) -> None: ...
    def forget(self, device_id: str) -> None: ...


class MemorySeqStore:
    """Forgets everything on restart; ``Opener`` compensates with a start-up window."""

    persistent = False

    def __init__(self) -> None:
        self._seqs: dict[str, int] = {}

    def get(self, device_id: str) -> int:
        return self._seqs.get(device_id, 0)

    def set(self, device_id: str, seq: int) -> None:
        self._seqs[device_id] = seq

    def forget(self, device_id: str) -> None:
        self._seqs.pop(device_id, None)


class JsonFileSeqStore:
    """Keeps sequence numbers in a JSON file, written atomically on every change."""

    persistent = True

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            data = {}
        if not isinstance(data, dict) or not all(
            isinstance(k, str) and type(v) is int for k, v in data.items()
        ):
            raise ValueError(f"{self._path} is not a lanpair sequence file")
        self._seqs: dict[str, int] = data

    def get(self, device_id: str) -> int:
        return self._seqs.get(device_id, 0)

    def set(self, device_id: str, seq: int) -> None:
        with self._lock:
            self._seqs[device_id] = seq
            self._write()

    def forget(self, device_id: str) -> None:
        with self._lock:
            if self._seqs.pop(device_id, None) is not None:
                self._write()

    def _write(self) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".lanpair-seq-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(self._seqs, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


def _canonical(fields: dict[str, Any]) -> bytes:
    return json.dumps(
        fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode()


def _signed_fields(sender: str, recipient: str, ts: float, seq: int, body: Any) -> dict[str, Any]:
    return {"v": VERSION, "from": sender, "to": recipient, "ts": ts, "seq": seq, "body": body}


@dataclass
class Sealer:
    """Signs outgoing messages. One sealer can serve every recipient."""

    identity: Identity
    clock: Callable[[], float] = time.time
    _seq: int = 0
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def _next_seq(self) -> int:
        # Microseconds since the epoch, or one more than the last: increases across restarts.
        with self._lock:
            self._seq = max(self._seq + 1, int(self.clock() * 1_000_000))
            return self._seq

    def seal(self, recipient: PublicIdentity, body: Any) -> bytes:
        fields = _signed_fields(
            self.identity.public.device_id,
            recipient.device_id,
            self.clock(),
            self._next_seq(),
            body,
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
    store: SeqStore = field(default_factory=MemorySeqStore)
    _started: float = field(init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __post_init__(self) -> None:
        self._started = self.clock()

    def add_peer(self, peer: PublicIdentity) -> None:
        self.peers[peer.device_id] = peer

    def remove_peer(self, device_id: str) -> None:
        self.peers.pop(device_id, None)
        self.store.forget(device_id)

    def open(self, raw: bytes) -> tuple[PublicIdentity, Any]:
        try:
            msg = json.loads(raw)
            sig = base64.b64decode(msg.pop("sig"), validate=True)
            fields = _signed_fields(msg["from"], msg["to"], msg["ts"], msg["seq"], msg["body"])
        except (ValueError, KeyError, TypeError, AttributeError) as e:
            raise EnvelopeError("malformed envelope") from e
        if msg.get("v") != VERSION or set(msg) != set(fields):
            raise EnvelopeError("unsupported envelope")
        sender, recipient, ts, seq = fields["from"], fields["to"], fields["ts"], fields["seq"]
        if not (
            isinstance(sender, str)
            and isinstance(recipient, str)
            and type(seq) is int
            and type(ts) in (int, float)
            and math.isfinite(ts)
        ):
            raise EnvelopeError("malformed envelope")

        peer = self.peers.get(sender)
        if peer is None:
            raise EnvelopeError("unknown sender")
        try:
            signed = _canonical(fields)
        except ValueError as e:
            raise EnvelopeError("malformed envelope") from e
        if not peer.verify(signed, sig):
            raise EnvelopeError("bad signature")
        if recipient != self.me.device_id:
            raise EnvelopeError("not addressed to this device")
        now = self.clock()
        if abs(now - ts) > self.max_skew:
            raise EnvelopeError("stale or future timestamp")
        if not self.store.persistent and ts < self._started + self.max_skew:
            raise EnvelopeError("sent before this receiver started")
        with self._lock:
            if seq <= self.store.get(peer.device_id):
                raise EnvelopeError("replayed message")
            self.store.set(peer.device_id, seq)
        return peer, fields["body"]
