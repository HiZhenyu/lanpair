import json

import pytest

from lanpair import EnvelopeError, Identity, JsonFileSeqStore, Opener, PublicIdentity, Sealer


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
    opener = Opener(room3, clock=clock)
    opener.add_peer(desk.public)
    clock.t += 31  # past the start-up window of the in-memory store
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


def test_body_is_not_readable_on_the_wire(setup):
    _, _, room3, _, sealer, _ = setup
    raw = sealer.seal(room3.public, {"secret": "door-code-4711"})
    assert b"door-code" not in raw and b"secret" not in raw


def test_other_paired_device_cannot_decrypt(setup):
    clock, desk, room3, room4, sealer, _ = setup
    raw = sealer.seal(room3.public, {"type": "close"})
    msg = json.loads(raw)
    msg["to"] = room4.public.device_id  # even with a re-signed header, room4 lacks the key
    fields = {k: v for k, v in msg.items() if k != "sig"}
    from lanpair.envelope import _b64, _canonical

    msg["sig"] = _b64(desk.sign(_canonical(fields)))
    other = Opener(room4, clock=clock)
    other.add_peer(desk.public)
    with pytest.raises(EnvelopeError):
        other.open(json.dumps(msg).encode())


def test_tampered_ciphertext_rejected(setup):
    _, _, room3, _, sealer, opener = setup
    msg = json.loads(sealer.seal(room3.public, {"type": "close"}))
    msg["ct"] = msg["ct"][:-4] + ("AAAA" if not msg["ct"].endswith("AAAA") else "BBBB")
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
    assert PublicIdentity.from_bytes(ident.public.to_bytes()) == ident.public
    assert ident.seed().hex() not in repr(ident)


def test_sender_restart_keeps_working(setup):
    clock, desk, room3, _, sealer, opener = setup
    opener.open(sealer.seal(room3.public, {}))
    clock.t += 1
    restarted = Sealer(desk, clock=clock)
    opener.open(restarted.seal(room3.public, {}))


def test_memory_store_rejects_replay_after_receiver_restart(setup):
    clock, desk, room3, _, sealer, _ = setup
    raw = sealer.seal(room3.public, {"type": "close"})
    clock.t += 1
    restarted = Opener(room3, clock=clock)
    restarted.add_peer(desk.public)
    with pytest.raises(EnvelopeError, match="before this receiver started"):
        restarted.open(raw)
    clock.t += 31
    restarted.open(sealer.seal(room3.public, {}))


def test_file_store_rejects_replay_after_receiver_restart(setup, tmp_path):
    clock, desk, room3, _, sealer, _ = setup
    path = tmp_path / "seq.json"
    first = Opener(room3, clock=clock, store=JsonFileSeqStore(path))
    first.add_peer(desk.public)
    raw = sealer.seal(room3.public, {"type": "close"})
    first.open(raw)
    restarted = Opener(room3, clock=clock, store=JsonFileSeqStore(path))
    restarted.add_peer(desk.public)
    with pytest.raises(EnvelopeError, match="replayed"):
        restarted.open(raw)
    restarted.open(sealer.seal(room3.public, {}))  # no start-up window with a file store


def test_file_store_rejects_bad_file(tmp_path):
    path = tmp_path / "seq.json"
    path.write_text('{"a": "1"}')
    with pytest.raises(ValueError):
        JsonFileSeqStore(path)


@pytest.mark.parametrize(
    "change",
    [
        {"from": ["x"]},
        {"to": 1},
        {"seq": True},
        {"seq": 1.5},
        {"ts": "now"},
        {"eph": 1},
        {"ct": None},
    ],
)
def test_wrong_types_rejected(setup, change):
    _, _, room3, _, sealer, opener = setup
    msg = json.loads(sealer.seal(room3.public, {}))
    msg.update(change)
    with pytest.raises(EnvelopeError, match="malformed"):
        opener.open(json.dumps(msg).encode())


@pytest.mark.parametrize("bad", [b"NaN", b"Infinity", b"-Infinity"])
def test_non_finite_timestamp_rejected(setup, bad):
    _, _, room3, _, sealer, opener = setup
    raw = sealer.seal(room3.public, {})
    msg = json.loads(raw)
    raw = raw.replace(json.dumps(msg["ts"]).encode(), bad)
    with pytest.raises(EnvelopeError, match="malformed"):
        opener.open(raw)


@pytest.mark.parametrize("raw", [b"[" * 200_000, b'{"a":' * 200_000])
def test_deeply_nested_json_rejected_not_crash(setup, raw):
    *_, opener = setup
    opener.max_size = 10 << 20
    with pytest.raises(EnvelopeError, match="malformed"):
        opener.open(raw)


def test_oversized_envelope_rejected(setup):
    _, _, room3, _, sealer, opener = setup
    raw = sealer.seal(room3.public, {"blob": "x" * 2_000_000})
    with pytest.raises(EnvelopeError, match="too large"):
        opener.open(raw)
    opener.max_size = 4 << 20
    assert opener.open(raw)[1]["blob"] == "x" * 2_000_000


# --- forward secrecy: session keys ------------------------------------------------------


def test_session_key_needed_and_seed_alone_cannot_decrypt(setup):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    clock, desk, room3, _, sealer, opener = setup
    session = opener.add_session_key(X25519PrivateKey.generate())
    raw = sealer.seal(room3.public, {"secret": 1}, box_key=session)
    # Someone who later steals room3's seed, but not the in-memory session key:
    thief = Opener(Identity.from_seed(room3.seed()), clock=clock)
    thief.add_peer(desk.public)
    thief._started = clock.t - 100  # past its start-up window
    with pytest.raises(EnvelopeError, match="cannot decrypt"):
        thief.open(raw)
    opened = opener.open_detailed(raw)
    assert opened.body == {"secret": 1} and opened.session_key == session


def test_removed_session_key_cannot_decrypt(setup):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    _, _, room3, _, sealer, opener = setup
    session = opener.add_session_key(X25519PrivateKey.generate())
    raw = sealer.seal(room3.public, "x", box_key=session)
    opener.remove_session_key(session)
    with pytest.raises(EnvelopeError, match="cannot decrypt"):
        opener.open(raw)


def test_long_term_key_still_works_with_session_keys(setup):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    _, _, room3, _, sealer, opener = setup
    opener.add_session_key(X25519PrivateKey.generate())
    opened = opener.open_detailed(sealer.seal(room3.public, "x"))
    assert opened.body == "x" and opened.session_key is None


def test_bad_box_key_rejected(setup):
    _, _, room3, _, sealer, _ = setup
    with pytest.raises(ValueError):
        sealer.seal(room3.public, "x", box_key=b"short")
