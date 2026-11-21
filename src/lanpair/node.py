"""The high-level API: a :class:`Host` and the :class:`Device` objects paired with it.

Everything is included: UDP transport, pairing by QR code, discovery with mDNS, keys in
the OS key store, and replay protection that survives restarts::

    host = Host("Front desk")                 # device side:
    host.start()                              # dev = Device("Room 3")
    host.pairing_offer().print_qr()           # dev.start()
    for msg in host.messages():               # dev.pair(scanned_text)
        print(msg.sender.name, msg.body)      # dev.send({"type": "close"})

Each message travels in one UDP datagram, so keep bodies under about 6 KB.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import re
import socket
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, NamedTuple, TypeVar

from .envelope import EnvelopeError, JsonFileSeqStore, Opener, Sealer
from .identity import Identity, PublicIdentity
from .pairing import PairingError, PairingOffer, PairingSession, make_request

_MSG = b"M"  # an envelope
_PAIR = b"P"  # a pairing request
MAX_DATAGRAM = 9000  # bytes; macOS refuses larger UDP datagrams by default
_POLL = 0.25  # seconds; how quickly the receive thread notices close()


@dataclass(frozen=True)
class PeerInfo:
    """A paired device (seen from the host) or the host (seen from a device)."""

    device_id: str
    name: str
    identity: PublicIdentity
    address: str | None  # last known "ip:port"


class Message(NamedTuple):
    """A message that passed every check: from a paired peer, intact, fresh, not a replay."""

    sender: PeerInfo
    body: Any


def _slug(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:40] or "device"


def _lan_ip() -> str:
    """The address other devices on the LAN reach this one at (no packet is sent)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))  # TEST-NET-1: picks the outgoing interface only
        return str(s.getsockname()[0])
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def _split(address: str) -> tuple[str, int]:
    host, port = address.rsplit(":", 1)
    return host.strip("[]"), int(port)


class _PeerBook:
    """Paired peers in a JSON file: identity, name, last known address. Atomic writes."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._lock = threading.Lock()
        self._peers: dict[str, PeerInfo] = {}
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            data = {}
        if not isinstance(data, dict):
            raise ValueError(f"{path} is not a lanpair peer file")
        for entry in data.values():
            ident = PublicIdentity.from_bytes(base64.b64decode(entry["id"]))
            self._peers[ident.device_id] = PeerInfo(
                ident.device_id, str(entry.get("name", "")), ident, entry.get("addr")
            )

    def all(self) -> list[PeerInfo]:
        with self._lock:
            return list(self._peers.values())

    def get(self, device_id: str) -> PeerInfo | None:
        with self._lock:
            return self._peers.get(device_id)

    def put(self, peer: PeerInfo) -> None:
        with self._lock:
            if self._peers.get(peer.device_id) == peer:
                return
            self._peers[peer.device_id] = peer
            self._write()

    def remove(self, device_id: str) -> None:
        with self._lock:
            if self._peers.pop(device_id, None) is not None:
                self._write()

    def _write(self) -> None:
        data = {
            p.device_id: {
                "id": base64.b64encode(p.identity.to_bytes()).decode(),
                "name": p.name,
                "addr": p.address,
            }
            for p in self._peers.values()
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self._path.parent, prefix=".lanpair-peers-")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=1)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise


_N = TypeVar("_N", bound="_Node")


class _Node:
    _role = "node"

    def __init__(
        self,
        name: str,
        *,
        app: str = "lanpair",
        port: int = 0,
        state_dir: str | os.PathLike[str] | None = None,
        identity: Identity | None = None,
        announce: bool = True,
        bind: str = "0.0.0.0",
    ) -> None:
        from .discovery import service_type

        service_type(app)  # validates the app name early
        self.name = name[:63]
        self.app = app
        slug = f"{self._role}-{_slug(name)}"
        if identity is None:
            from .keystore import load_or_create_identity

            identity = load_or_create_identity(f"{app}/{slug}")
        self.identity = identity
        self.state_dir = Path(state_dir) if state_dir else Path.home() / ".lanpair" / app / slug
        self._book = _PeerBook(self.state_dir / "peers.json")
        self._opener = Opener(identity, store=JsonFileSeqStore(self.state_dir / "seqs.json"))
        for peer in self._book.all():
            self._opener.add_peer(peer.identity)
        self._sealer = Sealer(identity)
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # All interfaces by default: other devices on the LAN must reach this one. Every
        # datagram is authenticated before use. Pass bind="192.168.1.10" to listen on one
        # interface only (e.g. not on a VPN or a public network).
        self._sock.bind((bind, port))
        self._sock.settimeout(_POLL)
        self._announce = announce
        self._announcer: Any = None
        self._inbox: queue.Queue[Message] = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self.dropped = 0
        """Datagrams refused so far (forged, tampered, replayed, garbage, ...)."""

    # --- lifecycle ---------------------------------------------------------------------

    @property
    def device_id(self) -> str:
        return self.identity.public.device_id

    @property
    def port(self) -> int:
        return int(self._sock.getsockname()[1])

    def start(self) -> None:
        """Start receiving, and announce this device on the network (unless announce=False)."""
        if self._thread is not None:
            return
        if self._announce:
            from .discovery import Announcer

            self._announcer = Announcer(self.identity.public, self.name, self.port, app=self.app)
        self._thread = threading.Thread(target=self._run, name=f"lanpair-{self.name}", daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=5)
        if self._announcer is not None:
            self._announcer.close()
            self._announcer = None
        self._sock.close()

    def __enter__(self: _N) -> _N:
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # --- receiving ---------------------------------------------------------------------

    def receive(self, timeout: float | None = None) -> Message | None:
        """The next message, or None after *timeout* seconds."""
        try:
            return self._inbox.get(timeout=timeout)
        except queue.Empty:
            return None

    def messages(self) -> Iterator[Message]:
        """Every message, as it arrives, until :meth:`close`."""
        while not self._stop.is_set():
            msg = self.receive(timeout=_POLL)
            if msg is not None:
                yield msg

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(65535)
            except TimeoutError:
                continue
            except OSError:
                # Closed by close(), or (Windows) an ICMP "port unreachable" for an earlier
                # send surfacing here as ConnectionResetError: keep listening.
                if self._stop.is_set():
                    return
                continue
            try:
                self._handle(data, f"{addr[0]}:{addr[1]}")
            except (EnvelopeError, PairingError, ValueError):
                self.dropped += 1

    def _handle(self, data: bytes, source: str) -> None:
        kind, payload = data[:1], data[1:]
        if kind == _PAIR:
            self._on_pair_request(payload, source)
            return
        if kind != _MSG:
            raise ValueError("unknown datagram")
        ident, body = self._opener.open(payload)
        known = self._book.get(ident.device_id)
        if known is None:  # unpaired between the check and now
            raise ValueError("unknown peer")
        peer = PeerInfo(known.device_id, known.name, known.identity, source)
        self._book.put(peer)  # follow the peer to its current address
        if not isinstance(body, dict):
            raise ValueError("not a lanpair message")
        if "msg" in body:
            self._inbox.put(Message(peer, body["msg"]))
        elif "lanpair" in body:
            self._on_control(peer, body)

    def _on_pair_request(self, payload: bytes, source: str) -> None:
        raise PairingError("this device does not accept pairing requests")

    def _on_control(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        pass

    # --- sending -----------------------------------------------------------------------

    def _add_peer(self, peer: PeerInfo) -> None:
        self._book.put(peer)
        self._opener.add_peer(peer.identity)

    def _resolve(self, peer: PeerInfo) -> str:
        if peer.address:
            return peer.address
        if self._announce:
            from .discovery import find

            found = find(peer.device_id, seconds=2.0, app=self.app)
            if found is not None:
                self._book.put(PeerInfo(peer.device_id, peer.name, peer.identity, found.address))
                return found.address
        raise LookupError(f"don't know where {peer.name or peer.device_id} is")

    def _send(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        data = _MSG + self._sealer.seal(peer.identity, body)
        if len(data) > MAX_DATAGRAM:
            raise ValueError(f"message too large for one datagram ({len(data)} bytes)")
        self._sock.sendto(data, _split(self._resolve(peer)))


class Host(_Node):
    """The side that shows the QR code and that many devices pair with (a front desk, a hub).

    ``Host(name)`` keeps its keys in the OS key store (needs ``lanpair[keyring]``) and its
    paired devices and sequence numbers in ``~/.lanpair/<app>/host-<name>/``. Pass
    ``identity=`` and ``state_dir=`` to choose yourself. ``announce=False`` turns off mDNS
    (then devices must reach the address in the QR code). It listens on all interfaces;
    ``bind="<ip>"`` limits it to one, and ``port=`` fixes the port.
    """

    _role = "host"

    def __init__(self, name: str, **kwargs: Any) -> None:
        super().__init__(name, **kwargs)
        self._session: PairingSession | None = None
        self._paired_events: queue.Queue[PeerInfo] = queue.Queue()

    @property
    def devices(self) -> list[PeerInfo]:
        """Every paired device."""
        return self._book.all()

    def pairing_offer(
        self, *, ttl: float = 300.0, max_attempts: int = 5, address: str | None = None
    ) -> PairingOffer:
        """A new one-time offer to show as a QR code (``offer.print_qr()``, ``offer.to_uri()``).

        Valid for *ttl* seconds and for one device; it is locked after *max_attempts* wrong
        answers. Making a new offer cancels the previous one.
        """
        offer = PairingOffer.create(
            self.identity.public,
            self.name,
            address or f"{_lan_ip()}:{self.port}",
            ttl=ttl,
            app=self.app,
        )
        self._session = PairingSession(self.identity, offer, max_attempts=max_attempts)
        return offer

    def wait_for_pairing(self, timeout: float | None = None) -> PeerInfo | None:
        """The next device that pairs, or None after *timeout* seconds."""
        try:
            return self._paired_events.get(timeout=timeout)
        except queue.Empty:
            return None

    def send(self, device_id: str, body: Any) -> None:
        """Send *body* (any JSON value) to a paired device."""
        peer = self._book.get(device_id)
        if peer is None:
            raise LookupError(f"no paired device {device_id}")
        self._send(peer, {"msg": body})

    def unpair(self, device_id: str) -> None:
        """Forget a device: nothing from it is accepted any more."""
        self._book.remove(device_id)
        self._opener.remove_peer(device_id)

    def _on_pair_request(self, payload: bytes, source: str) -> None:
        session = self._session
        if session is None:
            raise PairingError("no pairing offer is open")
        ident, name = session.accept(payload)
        known = self._book.get(ident.device_id)
        peer = PeerInfo(ident.device_id, name, ident, source)
        self._add_peer(peer)
        self._send(peer, {"lanpair": "paired", "name": self.name})
        if known is None:
            self._paired_events.put(peer)


class Device(_Node):
    """The side that scans the host's QR code (a room PC, a phone, a sensor).

    Same storage and options as :class:`Host`.
    """

    _role = "device"

    def __init__(self, name: str, **kwargs: Any) -> None:
        super().__init__(name, **kwargs)
        self._confirmed = threading.Event()
        self._pending: str | None = None  # the host being paired with right now
        self._host_id: str | None = None
        peers = self._book.all()
        if peers:
            self._host_id = peers[0].device_id

    @property
    def host(self) -> PeerInfo | None:
        """The host this device is paired with, if any."""
        return self._book.get(self._host_id) if self._host_id else None

    def pair(self, offer: str | PairingOffer, *, timeout: float = 10.0) -> PeerInfo:
        """Pair with the host whose QR code was scanned (the text, or a parsed offer).

        Returns the host. Raises :class:`PairingError` if the offer is invalid, expired or
        for another app, or if the host does not confirm within *timeout* seconds.
        """
        if self._thread is None:
            raise PairingError("call start() before pair()")
        if isinstance(offer, str):
            offer = PairingOffer.from_uri(offer)
        if offer.app != self.app:
            raise PairingError(f"this offer is for app {offer.app!r}, not {self.app!r}")
        if offer.expired():
            raise PairingError("this pairing offer has expired")
        previous = self.host
        host = PeerInfo(offer.host.device_id, offer.name, offer.host, offer.address)
        self._add_peer(host)
        self._pending = host.device_id
        self._confirmed.clear()
        attempts = max(1, int(timeout // 2))
        for _ in range(attempts):
            request = make_request(self.identity, offer, self.name, self._sealer)
            self._sock.sendto(_PAIR + request, _split(offer.address))
            if self._confirmed.wait(timeout / attempts):
                if previous is not None and previous.device_id != host.device_id:
                    self._book.remove(previous.device_id)
                    self._opener.remove_peer(previous.device_id)
                self._host_id = host.device_id
                result = self._book.get(host.device_id)
                assert result is not None
                return result
        if previous is None or previous.device_id != host.device_id:
            self._book.remove(host.device_id)
            self._opener.remove_peer(host.device_id)
        raise PairingError("the host did not confirm the pairing")

    def send(self, body: Any) -> None:
        """Send *body* (any JSON value) to the host."""
        host = self.host
        if host is None:
            raise LookupError("not paired with a host yet: call pair() first")
        self._send(host, {"msg": body})

    def unpair(self) -> None:
        """Forget the host."""
        if self._host_id:
            self._book.remove(self._host_id)
            self._opener.remove_peer(self._host_id)
            self._host_id = None

    def _on_control(self, peer: PeerInfo, body: dict[str, Any]) -> None:
        if body.get("lanpair") == "paired" and peer.device_id == self._pending:
            name = body.get("name")
            if isinstance(name, str) and name:
                self._book.put(PeerInfo(peer.device_id, name[:63], peer.identity, peer.address))
            self._confirmed.set()
