import json

import pytest

from lanpair import Identity, PairingError, PairingOffer, Sealer
from lanpair.pairing import PairingSession, make_request


class Clock:
    def __init__(self) -> None:
        self.t = 1_000_000.0

    def __call__(self) -> float:
        return self.t


@pytest.fixture
def setup():
    clock = Clock()
    host, dev = Identity.generate(), Identity.generate()
    offer = PairingOffer.create(host.public, "Desk", "10.0.0.2:4000", ttl=300, clock=clock)
    session = PairingSession(host, offer, clock=clock)
    return clock, host, dev, offer, session


_sealers: dict = {}


def request(dev, offer, clock, secret=None):
    """A request from *dev*; one sealer per device, so sequence numbers keep increasing."""
    if secret is not None:
        offer = PairingOffer(offer.host, offer.name, offer.address, secret, offer.expires)
    sealer = _sealers.setdefault(dev, Sealer(dev, clock=clock))
    return make_request(dev, offer, "Room 3", sealer)


def test_uri_round_trip_and_secret_hidden(setup):
    *_, offer, _ = setup
    uri = offer.to_uri()
    assert uri.startswith("lanpair://pair?")
    assert PairingOffer.from_uri(uri) == offer
    assert offer.secret.hex() not in repr(offer)


def test_names_with_spaces_and_unicode_survive(setup):
    clock, host, *_ = setup
    offer = PairingOffer.create(host.public, "Réception & bar", "10.0.0.2:4000", clock=clock)
    assert PairingOffer.from_uri(offer.to_uri()).name == "Réception & bar"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda u: u.replace("lanpair://", "http://"),
        lambda u: u.replace("v=1", "v=2"),
        lambda u: u.replace("10.0.0.2%3A4000", "10.0.0.2%3A99999"),
        lambda u: u.replace("10.0.0.2%3A4000", "evil%20host%3A1"),
        lambda u: u.split("&s=")[0],
        lambda u: u.replace("&s=", "&s=AA"),
        lambda u: u.replace("&id=", "&id=AA"),
        lambda u: "not a link",
    ],
)
def test_bad_links_rejected(setup, mutate):
    *_, offer, _ = setup
    with pytest.raises(PairingError):
        PairingOffer.from_uri(mutate(offer.to_uri()))


def test_right_secret_pairs(setup):
    clock, _, dev, offer, session = setup
    ident, name = session.accept(request(dev, offer, clock))
    assert ident == dev.public and name == "Room 3"
    assert not session.open


def test_wrong_secret_refused_and_locks_after_max(setup):
    clock, _, dev, offer, session = setup
    for _ in range(5):
        with pytest.raises(PairingError, match="wrong"):
            session.accept(request(dev, offer, clock, secret=bytes(16)))
    with pytest.raises(PairingError, match="expired, used or locked"):
        session.accept(request(dev, offer, clock))  # even the right secret, now


def test_expired_offer_refused(setup):
    clock, _, dev, offer, session = setup
    clock.t += 301
    with pytest.raises(PairingError, match="expired"):
        session.accept(request(dev, offer, clock))


def test_offer_works_for_one_device_only(setup):
    clock, _, dev, offer, session = setup
    session.accept(request(dev, offer, clock))
    other = Identity.generate()
    with pytest.raises(PairingError, match="already used"):
        session.accept(request(other, offer, clock))


def test_same_device_may_retry_but_replay_refused(setup):
    clock, _, dev, offer, session = setup
    first = request(dev, offer, clock)
    session.accept(first)
    clock.t += 1
    assert session.accept(request(dev, offer, clock))[0] == dev.public  # lost confirmation
    with pytest.raises(PairingError, match="replayed"):
        session.accept(first)


def test_identity_swap_refused(setup):
    clock, _, dev, offer, session = setup
    wrapper = json.loads(request(dev, offer, clock))
    attacker = Identity.generate()
    wrapper["id"] = json.loads(request(attacker, offer, clock))["id"]
    with pytest.raises(PairingError, match="rejected"):
        session.accept(json.dumps(wrapper).encode())


@pytest.mark.parametrize("raw", [b"", b"{}", b"[]", b'{"id": 1, "env": 2}', b"[" * 100_000])
def test_garbage_refused(setup, raw):
    *_, session = setup
    with pytest.raises(PairingError):
        session.accept(raw)


def test_qr_code(setup):
    *_, offer, _ = setup
    qr = offer.qr()
    assert qr.designator  # e.g. "6-M"
