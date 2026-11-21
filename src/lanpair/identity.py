"""A device's long-term identity: an Ed25519 signing key and an X25519 encryption key.

Both keys come from one 32-byte seed, so storing the seed is enough to restore the device.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_RAW = serialization.Encoding.Raw
_PUB = serialization.PublicFormat.Raw


@dataclass(frozen=True)
class PublicIdentity:
    """Another device's public keys. Safe to share and store."""

    key: bytes
    """Ed25519 public key, for verifying signatures."""
    box_key: bytes
    """X25519 public key, for encrypting messages to this device."""

    def __post_init__(self) -> None:
        if len(self.key) != 32 or len(self.box_key) != 32:
            raise ValueError("lanpair public keys are 32 bytes each")

    @property
    def device_id(self) -> str:
        """Stable short id derived from the signing key."""
        return hashlib.sha256(self.key).hexdigest()[:16]

    def to_bytes(self) -> bytes:
        """64 bytes: signing key, then encryption key. Use this for QR codes and storage."""
        return self.key + self.box_key

    @classmethod
    def from_bytes(cls, raw: bytes) -> PublicIdentity:
        if len(raw) != 64:
            raise ValueError("a lanpair public identity is 64 bytes")
        return cls(raw[:32], raw[32:])

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.key).verify(signature, data)
        except (InvalidSignature, ValueError):
            return False
        return True


class Identity:
    """This device's key pair. The private keys never leave the process."""

    def __init__(self, seed: bytes) -> None:
        if len(seed) != 32:
            raise ValueError("a lanpair seed is 32 bytes")
        self._seed = bytes(seed)
        self._key = Ed25519PrivateKey.from_private_bytes(self._seed)
        box_seed = HKDF(hashes.SHA256(), 32, salt=None, info=b"lanpair x25519 v1").derive(seed)
        self._box = X25519PrivateKey.from_private_bytes(box_seed)
        self._public = PublicIdentity(
            self._key.public_key().public_bytes(_RAW, _PUB),
            self._box.public_key().public_bytes(_RAW, _PUB),
        )

    @classmethod
    def generate(cls) -> Identity:
        return cls(os.urandom(32))

    @classmethod
    def from_seed(cls, seed: bytes) -> Identity:
        return cls(seed)

    def seed(self) -> bytes:
        """Raw 32-byte private seed, for handing to a secure key store."""
        return self._seed

    @property
    def public(self) -> PublicIdentity:
        return self._public

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def exchange(self, peer_box_key: bytes) -> bytes:
        """X25519 shared secret with another public encryption key."""
        return self._box.exchange(X25519PublicKey.from_public_bytes(peer_box_key))

    def __repr__(self) -> str:  # never leak the key in logs
        return f"Identity(device_id={self.public.device_id!r})"
