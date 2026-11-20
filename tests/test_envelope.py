import json

import pytest

from lanpair import EnvelopeError, Identity, Opener, Sealer


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def setup():
    clock = Clock()
    desk, room3, room4 = Identity.generate(), Identity.generate(), Identity.generate()
    sealer = Sealer(desk, clock=clock)
    opener = Opener(room3.public, clock=clock)
    opener.add_peer(desk.public)
    return clock, desk, room3, room4, sealer, opener


def test_roundtrip(setup):
    _, desk, room3, _, sealer, opener = setup
    peer, body = opener.open(sealer.seal(room3.public, {"type": "close"}))
    assert peer == desk.public
    assert body == {"type": "close"}


def test_message_for_other_room_rejected(setup):
    _, _, _, room4, sealer, opener = setup
    with pytest.raises(EnvelopeError, match="not addressed"):
        opener.open(sealer.seal(room4.public, {"type": "close"}))


def test_replay_rejected(setup):
    _, _, room3, _, sealer, opener = setup
    raw = sealer.seal(room3.public, {"type": "close"})
    opener.open(raw)
    with pytest.raises(EnvelopeError, match="replayed"):
        opener.open(raw)


def test_stale_rejected(setup):
    clock, _, room3, _, sealer, opener = setup
    raw = sealer.seal(room3.public, {})
    clock.t += 31
    with pytest.raises(EnvelopeError, match="timestamp"):
        opener.open(raw)


def test_tampered_body_rejected(setup):
    _, _, room3, _, sealer, opener = setup
    msg = json.loads(sealer.seal(room3.public, {"type": "close"}))
    msg["body"] = {"type": "open"}
    with pytest.raises(EnvelopeError, match="bad signature"):
        opener.open(json.dumps(msg).encode())


def test_unknown_sender_rejected(setup):
    clock, _, room3, _, _, opener = setup
    impostor = Sealer(Identity.generate(), clock=clock)
    with pytest.raises(EnvelopeError, match="unknown sender"):
        opener.open(impostor.seal(room3.public, {}))


def test_unpaired_peer_rejected(setup):
    _, desk, room3, _, sealer, opener = setup
    opener.remove_peer(desk.public.device_id)
    with pytest.raises(EnvelopeError, match="unknown sender"):
        opener.open(sealer.seal(room3.public, {}))


@pytest.mark.parametrize("raw", [b"", b"{}", b"[]", b'{"sig": "!!"}', b"\xff"])
def test_garbage_rejected(setup, raw):
    *_, opener = setup
    with pytest.raises(EnvelopeError):
        opener.open(raw)


def test_seed_roundtrip_and_repr():
    ident = Identity.generate()
    assert Identity.from_seed(ident.seed()).public == ident.public
    assert ident.seed().hex() not in repr(ident)
