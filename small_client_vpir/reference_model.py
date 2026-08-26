"""Transparent, deterministic-friendly FHE stand-in for protocol tests.

The ciphertext contains the plaintext.  It is useful for checking dimensions,
state transitions, proof equations and failure paths, but it provides neither
query privacy nor FHE security.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from .algebra import Matrix, as_matrix, matmul, matrix_logical_bytes
from .primitives import FHEBackend, FHEKeyPair


@dataclass(frozen=True)
class TransparentCiphertext:
    payload: Matrix
    key_tag: bytes


class TransparentFHEBackend(FHEBackend):
    @property
    def name(self) -> str:
        return "transparent-reference-fhe"

    @property
    def cryptographically_secure(self) -> bool:
        return False

    def bind_context(
        self,
        *,
        context_digest_hex: str,
        profile_digest_hex: str,
        role: str,
        plaintext_modulus: int,
    ) -> str:
        if role not in {"client-registration-lhe", "hint-delegation-fhe"}:
            raise ValueError("unsupported transparent-backend role")
        if plaintext_modulus <= 1:
            raise ValueError("invalid transparent-backend plaintext modulus")
        for label, digest in (
            ("context", context_digest_hex),
            ("profile", profile_digest_hex),
        ):
            if len(digest) != 64 or any(
                character not in "0123456789abcdef" for character in digest.lower()
            ):
                raise ValueError(f"invalid {label} digest")
        return context_digest_hex

    def keygen(self) -> FHEKeyPair:
        tag = secrets.token_bytes(16)
        return FHEKeyPair(secret_key=tag, evaluation_key=tag)

    def encrypt(self, secret_key: Any, plaintext: Matrix) -> TransparentCiphertext:
        if not isinstance(secret_key, bytes) or len(secret_key) != 16:
            raise TypeError("invalid transparent reference key")
        return TransparentCiphertext(as_matrix(plaintext), secret_key)

    def evaluate_left_matrix(
        self,
        evaluation_key: Any,
        left_matrix: Matrix,
        ciphertext: Any,
        *,
        modulus: int,
    ) -> TransparentCiphertext:
        if not isinstance(ciphertext, TransparentCiphertext):
            raise TypeError("invalid transparent ciphertext")
        if evaluation_key != ciphertext.key_tag:
            raise ValueError("evaluation key does not match ciphertext")
        return TransparentCiphertext(
            matmul(as_matrix(left_matrix), ciphertext.payload, modulus=modulus),
            ciphertext.key_tag,
        )

    def decrypt(self, secret_key: Any, ciphertext: Any) -> Matrix:
        if not isinstance(ciphertext, TransparentCiphertext):
            raise TypeError("invalid transparent ciphertext")
        if secret_key != ciphertext.key_tag:
            raise ValueError("decryption key does not match ciphertext")
        return ciphertext.payload

    def logical_ciphertext_bytes(self, ciphertext: Any, *, modulus: int) -> int:
        if not isinstance(ciphertext, TransparentCiphertext):
            raise TypeError("invalid transparent ciphertext")
        return 16 + matrix_logical_bytes(ciphertext.payload, modulus)
