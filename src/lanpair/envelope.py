"""Encrypted, signed message envelopes bound to a recipient, with replay protection.

Bodies are encrypted to the recipient (X25519 with a fresh key per message, HKDF-SHA256,
ChaCha20-Poly1305), so they cannot be read on the LAN. The ciphertext is bound to the
header as associated data, and the signature covers version, sender, recipient,
timestamp, sequence number and ciphertext, so a message meant for one device cannot be
redirected to another, and a recorded message cannot be played back later, also not
after either side restarts:

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

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .identity import Identity, PublicIdentity

VERSION = 2
DEFAULT_MAX_SKEW = 30.0  # seconds
DEFAULT_MAX_SIZE = 1 << 20  # bytes; larger envelopes are refused before parsing
_NONCE = bytes(12)  # every message has its own key, so a fixed nonce is safe


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


def _signed_fields(
    sender: str, recipient: str, ts: float, seq: int, eph: str, ct: str
) -> dict[str, Any]:
    return {
        "v": VERSION,
        "from": sender,
        "to": recipient,
        "ts": ts,
        "seq": seq,
        "eph": eph,
        "ct": ct,
    }


def _body_key(shared: bytes, eph_pub: bytes, recipient_box: bytes) -> bytes:
    hkdf = HKDF(hashes.SHA256(), 32, salt=eph_pub + recipient_box, info=b"lanpair body v2")
    return hkdf.derive(shared)


def _header(fields: dict[str, Any]) -> bytes:
    """Everything except the ciphertext, used as AEAD associated data."""
    return _canonical({k: v for k, v in fields.items() if k != "ct"})


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


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
        plaintext = _canonical({"body": body})
        eph = X25519PrivateKey.generate()
        eph_pub = eph.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        shared = eph.exchange(X25519PublicKey.from_public_bytes(recipient.box_key))
        key = _body_key(shared, eph_pub, recipient.box_key)
        fields = _signed_fields(
            self.identity.public.device_id,
            recipient.device_id,
            self.clock(),
            self._next_seq(),
            _b64(eph_pub),
            "",
        )
        fields["ct"] = _b64(ChaCha20Poly1305(key).encrypt(_NONCE, plaintext, _header(fields)))
        sig = self.identity.sign(_canonical(fields))
        return _canonical({**fields, "sig": _b64(sig)})


@dataclass
class Opener:
    """Verifies and decrypts incoming messages for this device against paired peers."""

    me: Identity
    peers: dict[str, PublicIdentity] = field(default_factory=dict)
    clock: Callable[[], float] = time.time
    max_skew: float = DEFAULT_MAX_SKEW
    max_size: int = DEFAULT_MAX_SIZE
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
        if len(raw) > self.max_size:
            raise EnvelopeError("envelope too large")
        try:
            msg = json.loads(raw)
            sig = base64.b64decode(msg.pop("sig"), validate=True)
            fields = _signed_fields(
                msg["from"], msg["to"], msg["ts"], msg["seq"], msg["eph"], msg["ct"]
            )
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError) as e:
            raise EnvelopeError("malformed envelope") from e
        if msg.get("v") != VERSION or set(msg) != set(fields):
            raise EnvelopeError("unsupported envelope")
        sender, recipient, ts, seq = fields["from"], fields["to"], fields["ts"], fields["seq"]
        if not (
            isinstance(sender, str)
            and isinstance(recipient, str)
            and isinstance(fields["eph"], str)
            and isinstance(fields["ct"], str)
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
        if recipient != self.me.public.device_id:
            raise EnvelopeError("not addressed to this device")
        now = self.clock()
        if abs(now - ts) > self.max_skew:
            raise EnvelopeError("stale or future timestamp")
        if not self.store.persistent and ts < self._started + self.max_skew:
            raise EnvelopeError("sent before this receiver started")
        with self._lock:
            if seq <= self.store.get(peer.device_id):
                raise EnvelopeError("replayed message")
            body = self._decrypt(fields)
            self.store.set(peer.device_id, seq)
        return peer, body

    def _decrypt(self, fields: dict[str, Any]) -> Any:
        try:
            eph_pub = base64.b64decode(fields["eph"], validate=True)
            ct = base64.b64decode(fields["ct"], validate=True)
            box = self.me.public.box_key
            key = _body_key(self.me.exchange(eph_pub), eph_pub, box)
            plaintext = ChaCha20Poly1305(key).decrypt(_NONCE, ct, _header(fields))
            return json.loads(plaintext)["body"]
        except (ValueError, KeyError, TypeError, InvalidTag, RecursionError) as e:
            raise EnvelopeError("cannot decrypt") from e
