"""Envelope encryption helpers.

Each sensitive field gets its own Data Encryption Key (DEK). The DEK
encrypts the plaintext; the DEK itself is then "wrapped" (encrypted)
under a single master Key-Encryption-Key (KEK) pulled from the
KEK_SECRET env var, and only the wrapped DEK is stored alongside the
ciphertext. Compromising one stored row never exposes the KEK, and
rotating the KEK only requires re-wrapping DEKs, not re-encrypting data.
"""

import os

from cryptography.fernet import Fernet


def _kek() -> Fernet:
    secret = os.environ["KEK_SECRET"]
    return Fernet(secret.encode())


def generate_dek() -> bytes:
    return Fernet.generate_key()


def encrypt_with_dek(dek: bytes, plaintext: str) -> str:
    return Fernet(dek).encrypt(plaintext.encode()).decode()


def decrypt_with_dek(dek: bytes, ciphertext: str) -> str:
    return Fernet(dek).decrypt(ciphertext.encode()).decode()


def wrap_dek(dek: bytes) -> str:
    return _kek().encrypt(dek).decode()


def unwrap_dek(wrapped: str) -> bytes:
    return _kek().decrypt(wrapped.encode())
