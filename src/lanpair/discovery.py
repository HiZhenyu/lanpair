"""Find lanpair devices on the local network with mDNS / DNS-SD (zeroconf).

Discovery only says *where* a device claims to be. Anyone on the LAN can announce
anything, so never trust what it returns: the device id and name are hints for finding
the address of a peer you already paired with. Trust comes from pairing and from the
signature on every message.

Needs the zeroconf package: ``pip install "lanpair[discovery]"``.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .identity import PublicIdentity

DEFAULT_APP = "lanpair"
_APP = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,13}[a-z0-9])?$")
_DEVICE_ID = re.compile(r"^[0-9a-f]{16}$")
_MAX_NAME = 63


class DiscoveryError(Exception):
    """zeroconf is missing, or an announcement could not be made."""


@dataclass(frozen=True)
class FoundDevice:
    """A device that announced itself. Unverified: see the module docstring."""

    device_id: str
    name: str
    addresses: tuple[str, ...]
    port: int

    @property
    def address(self) -> str:
        """The first address as ``host:port`` (IPv6 in brackets)."""
        host = self.addresses[0]
        return f"[{host}]:{self.port}" if ":" in host else f"{host}:{self.port}"


def service_type(app: str = DEFAULT_APP) -> str:
    """The DNS-SD service type for *app*; apps with different names don't see each other."""
    if not _APP.match(app):
        raise ValueError("app must be 1-15 lowercase letters, digits or inner hyphens")
    return f"_{app}._tcp.local."


def _zeroconf() -> Any:
    try:
        import zeroconf
    except ImportError as e:  # pragma: no cover - depends on the install
        raise DiscoveryError(
            'discovery needs the zeroconf package: pip install "lanpair[discovery]"'
        ) from e
    return zeroconf


def _parse(
    properties: Mapping[bytes, bytes | None], addresses: list[str], port: int
) -> FoundDevice | None:
    """A FoundDevice from an announcement, or None if it is not a valid lanpair one."""
    try:
        props = {k.decode(): (v or b"").decode() for k, v in properties.items()}
    except UnicodeDecodeError:
        return None
    device_id = props.get("id", "")
    if props.get("v") != "1" or not _DEVICE_ID.match(device_id):
        return None
    if not addresses or not 0 < port < 65536:
        return None
    name = props.get("name", "")[:_MAX_NAME] or device_id
    return FoundDevice(device_id, name, tuple(addresses), port)


def browse(seconds: float = 2.0, *, app: str = DEFAULT_APP) -> list[FoundDevice]:
    """Every device that answers within *seconds*, one entry per device id."""
    zc_mod = _zeroconf()
    stype = service_type(app)
    found: dict[str, FoundDevice] = {}
    lock = threading.Lock()

    class Listener(zc_mod.ServiceListener):  # type: ignore[misc,name-defined]
        def add_service(self, zc: Any, type_: str, name: str) -> None:
            info = zc.get_service_info(type_, name, timeout=1500)
            if info is None:
                return
            device = _parse(info.properties, info.parsed_scoped_addresses(), info.port or 0)
            if device is not None:
                with lock:
                    found[device.device_id] = device

        update_service = add_service

        def remove_service(self, zc: Any, type_: str, name: str) -> None:
            pass

    zc = zc_mod.Zeroconf()
    try:
        zc_mod.ServiceBrowser(zc, stype, Listener())
        time.sleep(seconds)
    finally:
        zc.close()
    with lock:
        return list(found.values())


def find(device_id: str, seconds: float = 2.0, *, app: str = DEFAULT_APP) -> FoundDevice | None:
    """Where the device with *device_id* says it is right now, or None."""
    for device in browse(seconds, app=app):
        if device.device_id == device_id:
            return device
    return None


def _local_addresses() -> list[str]:
    """This machine's IPv4 addresses that other LAN devices can reach."""
    _zeroconf()  # ifaddr comes with zeroconf
    import ifaddr

    addrs = []
    for adapter in ifaddr.get_adapters():
        for ip in adapter.ips:
            if isinstance(ip.ip, str):  # IPv4; IPv6 entries are tuples
                addr = ipaddress.ip_address(ip.ip)
                if not (addr.is_loopback or addr.is_link_local):
                    addrs.append(ip.ip)
    return addrs or ["127.0.0.1"]


class Announcer:
    """Tells the local network where this device listens, until closed.

    ``with Announcer(me.public, "Room 3", port=8765): ...``
    """

    def __init__(
        self,
        identity: PublicIdentity,
        name: str,
        port: int,
        *,
        addresses: list[str] | None = None,
        app: str = DEFAULT_APP,
    ) -> None:
        if not 0 < port < 65536:
            raise ValueError("port must be 1-65535")
        zc_mod = _zeroconf()
        stype = service_type(app)
        device_id = identity.device_id
        label = re.sub(r"[^\w -]", "", name)[:40].strip() or "device"
        self._info = zc_mod.ServiceInfo(
            stype,
            f"{label} {device_id[:6]}.{stype}",
            parsed_addresses=addresses or _local_addresses(),
            port=port,
            properties={"v": "1", "id": device_id, "name": name[:_MAX_NAME]},
        )
        self._zc = zc_mod.Zeroconf()
        try:
            self._zc.register_service(self._info, allow_name_change=True)
        except Exception as e:
            self._zc.close()
            raise DiscoveryError(f"could not announce on the network: {e}") from e
        self._closed = False

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self._zc.unregister_service(self._info)
        finally:
            self._zc.close()

    def __enter__(self) -> Announcer:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
