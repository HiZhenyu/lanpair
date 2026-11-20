"""A device's long-term Ed25519 identity."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

_RAW = serialization.Encoding.Raw


@dataclass(frozen=True)
class PublicIdentity:
    """Another device's public key. Safe to share and store."""

    key: bytes

    def __post_init__(self) -> None:
        if len(self.key) != 32:
            raise ValueError("Ed25519 public keys are 32 bytes")

    @property
    def device_id(self) -> str:
        """Stable short id derived from the public key."""
        return hashlib.sha256(self.key).hexdigest()[:16]

    def verify(self, data: bytes, signature: bytes) -> bool:
        try:
            Ed25519PublicKey.from_public_bytes(self.key).verify(signature, data)
        except (InvalidSignature, ValueError):
            return False
        return True


class Identity:
    """This device's key pair. The private key never leaves the process."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._key = private_key

    @classmethod
    def generate(cls) -> Identity:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_seed(cls, seed: bytes) -> Identity:
        return cls(Ed25519PrivateKey.from_private_bytes(seed))

    def seed(self) -> bytes:
        """Raw 32-byte private seed, for handing to a secure key store."""
        return self._key.private_bytes(
            _RAW, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )

    @property
    def public(self) -> PublicIdentity:
        raw = self._key.public_key().public_bytes(_RAW, serialization.PublicFormat.Raw)
        return PublicIdentity(raw)

    def sign(self, data: bytes) -> bytes:
        return self._key.sign(data)

    def __repr__(self) -> str:  # never leak the key in logs
        return f"Identity(device_id={self.public.device_id!r})"
