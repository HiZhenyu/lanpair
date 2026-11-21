"""Keep this device's identity in the operating system's key store.

macOS Keychain, Windows Credential Manager, or the Secret Service on Linux (GNOME
Keyring, KWallet), through the ``keyring`` package: ``pip install "lanpair[keyring]"``.
The seed never touches a plain file.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any

from .identity import Identity

SERVICE = "lanpair"


class KeyStoreError(Exception):
    """The key store is missing, locked, or holds something that is not a lanpair seed."""


def _keyring() -> Any:
    try:
        import keyring
        import keyring.errors
    except ImportError as e:  # pragma: no cover - depends on the install
        raise KeyStoreError(
            'the OS key store needs the keyring package: pip install "lanpair[keyring]"'
        ) from e
    return keyring


def load_identity(name: str = "default", *, service: str = SERVICE) -> Identity | None:
    """The identity stored under *name*, or ``None`` if there is none yet."""
    kr = _keyring()
    try:
        stored = kr.get_password(service, name)
    except kr.errors.KeyringError as e:
        raise KeyStoreError(f"cannot read the key store: {e}") from e
    if stored is None:
        return None
    try:
        return Identity.from_seed(base64.b64decode(stored, validate=True))
    except (binascii.Error, ValueError) as e:
        raise KeyStoreError(f"the key store entry {service}/{name} is not a lanpair seed") from e


def save_identity(identity: Identity, name: str = "default", *, service: str = SERVICE) -> None:
    """Store *identity* under *name*, replacing what was there."""
    kr = _keyring()
    try:
        kr.set_password(service, name, base64.b64encode(identity.seed()).decode())
    except kr.errors.KeyringError as e:
        raise KeyStoreError(f"cannot write to the key store: {e}") from e


def load_or_create_identity(name: str = "default", *, service: str = SERVICE) -> Identity:
    """This device's identity: the stored one, or a new one that is stored first.

    Call it on every start; the first call generates the keys, later calls return the same
    identity, also after a restart.
    """
    identity = load_identity(name, service=service)
    if identity is None:
        identity = Identity.generate()
        save_identity(identity, name, service=service)
    return identity


def delete_identity(name: str = "default", *, service: str = SERVICE) -> None:
    """Remove the stored identity. Paired devices will no longer recognise this one."""
    kr = _keyring()
    try:
        kr.delete_password(service, name)
    except kr.errors.PasswordDeleteError:
        pass
    except kr.errors.KeyringError as e:
        raise KeyStoreError(f"cannot delete from the key store: {e}") from e
