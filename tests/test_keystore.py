import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import KeyringLocked, PasswordDeleteError

from lanpair import Identity
from lanpair.keystore import (
    KeyStoreError,
    delete_identity,
    load_identity,
    load_or_create_identity,
    save_identity,
)


class MemoryKeyring(KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        super().__init__()
        self.items: dict[tuple[str, str], str] = {}
        self.locked = False

    def get_password(self, service, username):
        if self.locked:
            raise KeyringLocked("locked")
        return self.items.get((service, username))

    def set_password(self, service, username, password):
        self.items[(service, username)] = password

    def delete_password(self, service, username):
        if self.items.pop((service, username), None) is None:
            raise PasswordDeleteError("missing")


@pytest.fixture
def store():
    previous = keyring.get_keyring()
    backend = MemoryKeyring()
    keyring.set_keyring(backend)
    yield backend
    keyring.set_keyring(previous)


def test_first_call_creates_later_calls_return_same(store):
    first = load_or_create_identity()
    assert load_or_create_identity().public == first.public
    assert list(store.items) == [("lanpair", "default")]


def test_names_are_separate(store):
    a, b = load_or_create_identity("a"), load_or_create_identity("b")
    assert a.public != b.public


def test_save_load_delete(store):
    ident = Identity.generate()
    assert load_identity("x") is None
    save_identity(ident, "x")
    loaded = load_identity("x")
    assert loaded is not None and loaded.public == ident.public
    delete_identity("x")
    delete_identity("x")  # deleting twice is fine
    assert load_identity("x") is None


@pytest.mark.parametrize("bad", ["not base64!", "AAAA"])
def test_bad_entry_raises(store, bad):
    store.items[("lanpair", "default")] = bad
    with pytest.raises(KeyStoreError):
        load_identity()


def test_locked_store_raises(store):
    store.locked = True
    with pytest.raises(KeyStoreError, match="cannot read"):
        load_or_create_identity()
