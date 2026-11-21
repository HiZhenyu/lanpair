"""Host and Device over real UDP sockets on 127.0.0.1 (mDNS off, so it runs anywhere)."""

import time

import pytest

from lanpair import Device, Host, Identity, PairingError, PairingOffer


def make(cls, name, tmp_path, identity=None):
    node = cls(
        name,
        identity=identity or Identity.generate(),
        state_dir=tmp_path / name,
        announce=False,
        app="lanpair-test",
    )
    node.start()
    return node


@pytest.fixture
def pair(tmp_path):
    host = make(Host, "desk", tmp_path)
    dev = make(Device, "room3", tmp_path)
    offer = host.pairing_offer(address=f"127.0.0.1:{host.port}")
    dev.pair(offer.to_uri(), timeout=4)
    yield host, dev
    host.close()
    dev.close()


def wait(cond, timeout=3.0):
    end = time.time() + timeout
    while time.time() < end:
        if cond():
            return True
        time.sleep(0.02)
    return False


def test_pairing_both_sides_know_each_other(pair):
    host, dev = pair
    assert dev.host is not None and dev.host.device_id == host.device_id
    assert dev.host.name == "desk"
    joined = host.wait_for_pairing(timeout=2)
    assert joined is not None and joined.device_id == dev.device_id and joined.name == "room3"
    assert [d.device_id for d in host.devices] == [dev.device_id]


def test_messages_both_ways(pair):
    host, dev = pair
    dev.send({"type": "hello", "n": [1, 2]})
    msg = host.receive(timeout=2)
    assert msg is not None and msg.body == {"type": "hello", "n": [1, 2]}
    assert msg.sender.device_id == dev.device_id
    host.send(dev.device_id, {"type": "close"})
    msg = dev.receive(timeout=2)
    assert msg is not None and msg.body == {"type": "close"}


def test_survives_restart_without_pairing_again(pair, tmp_path):
    host, dev = pair
    ids = host.identity, dev.identity
    import socket

    # A real message from the device, sent and recorded the way an eavesdropper would.
    sniffed = b"M" + dev._sealer.seal(host.identity.public, {"msg": "before restart"})
    attacker = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    attacker.sendto(sniffed, ("127.0.0.1", host.port))
    assert host.receive(timeout=2).body == "before restart"
    host.close()
    dev.close()

    host2 = make(Host, "desk", tmp_path, identity=ids[0])
    dev2 = make(Device, "room3", tmp_path, identity=ids[1])
    try:
        # The host moved to a new port; tell the device (normally mDNS finds it).
        h = dev2.host
        dev2._book.put(type(h)(h.device_id, h.name, h.identity, f"127.0.0.1:{host2.port}"))
        dev2.send("after restart")
        assert host2.receive(timeout=2).body == "after restart"
        # A message recorded before the restart is refused.
        attacker.sendto(sniffed, ("127.0.0.1", host2.port))
        assert wait(lambda: host2.dropped >= 1)
        assert host2.receive(timeout=0.5) is None
    finally:
        host2.close()
        dev2.close()


def test_garbage_and_forgeries_are_dropped(pair):
    host, dev = pair
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    for junk in [b"", b"M", b"Mnot json", b"P{}", b"X" + b"[" * 8000, b"M" + b"{" * 8000]:
        s.sendto(junk, ("127.0.0.1", host.port))
    assert wait(lambda: host.dropped >= 6)
    dev.send("still works")
    assert host.receive(timeout=2).body == "still works"


def test_unpaired_device_is_ignored(pair):
    host, dev = pair
    host.unpair(dev.device_id)
    dev.send("ignored")
    assert wait(lambda: host.dropped >= 1)
    assert host.receive(timeout=0.5) is None
    with pytest.raises(LookupError):
        host.send(dev.device_id, "x")


def test_offer_is_single_use(pair, tmp_path):
    host, _ = pair
    offer = host.pairing_offer(address=f"127.0.0.1:{host.port}")
    second = make(Device, "room4", tmp_path)
    third = make(Device, "room5", tmp_path)
    try:
        second.pair(offer, timeout=2)
        with pytest.raises(PairingError, match="did not confirm"):
            third.pair(offer, timeout=2)
        assert third.host is None
        assert {d.name for d in host.devices} == {"room3", "room4"}
    finally:
        second.close()
        third.close()


def test_expired_and_foreign_offers_refused(tmp_path):
    host = make(Host, "desk", tmp_path)
    dev = make(Device, "room3", tmp_path)
    try:
        expired = host.pairing_offer(ttl=-1, address=f"127.0.0.1:{host.port}")
        with pytest.raises(PairingError, match="expired"):
            dev.pair(expired)
        other_app = PairingOffer.create(host.identity.public, "x", "127.0.0.1:1", app="other")
        with pytest.raises(PairingError, match="for app"):
            dev.pair(other_app)
    finally:
        host.close()
        dev.close()


def test_too_large_message_refused(pair):
    _, dev = pair
    with pytest.raises(ValueError, match="too large"):
        dev.send("x" * 20_000)


def test_send_before_pairing(tmp_path):
    dev = make(Device, "room3", tmp_path)
    try:
        with pytest.raises(LookupError):
            dev.send("x")
    finally:
        dev.close()


def test_keeps_receiving_after_sending_to_a_closed_port(pair):
    host, dev = pair
    import socket

    closed = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    closed.bind(("127.0.0.1", 0))
    port = closed.getsockname()[1]
    closed.close()
    joined = host.devices[0]
    host._book.put(
        type(joined)(joined.device_id, joined.name, joined.identity, f"127.0.0.1:{port}")
    )
    host.send(dev.device_id, "lost")  # Windows reports the closed port on the next receive
    time.sleep(0.3)
    dev.send("still listening")
    assert host.receive(timeout=2).body == "still listening"
