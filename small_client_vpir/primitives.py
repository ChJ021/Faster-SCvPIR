"""Cryptographic primitive interfaces for the Small-client vPIR profile.

The protocol module depends on these interfaces, not on a home-grown FHE
implementation.  The only bundled implementation is the transparent reference
backend in :mod:`small_client_vpir.reference_model`; it provides no secrecy.
"""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Callable, TypeVar

from .algebra import Matrix


@dataclass(frozen=True)
class FHEKeyPair:
    secret_key: Any
    evaluation_key: Any


_Result = TypeVar("_Result")
_LOCK_INITIALIZATION_GUARD = threading.Lock()


@dataclass(frozen=True)
class BoundFHEContext:
    """Immutable context-specific view of an FHE backend.

    Every operation rebinds and checks the complete context while holding the
    backend's operation lock.  Consequently, even a stateful native adapter
    cannot be switched to the other protocol role between context validation
    and the actual key/ciphertext operation.
    """

    backend: "FHEBackend"
    context_digest_hex: str
    profile_digest_hex: str
    role: str
    plaintext_modulus: int

    def _invoke(self, operation: Callable[[], _Result]) -> _Result:
        with self.backend._get_context_operation_lock():
            bound = self.backend.bind_context(
                context_digest_hex=self.context_digest_hex,
                profile_digest_hex=self.profile_digest_hex,
                role=self.role,
                plaintext_modulus=self.plaintext_modulus,
            )
            if bound != self.context_digest_hex:
                raise ValueError("backend did not bind the requested primitive context")
            return operation()

    def validate(self) -> None:
        """Validate the binding eagerly without weakening per-operation rebinding."""

        self._invoke(lambda: None)

    def keygen(self) -> FHEKeyPair:
        return self._invoke(self.backend.keygen)

    def encrypt(self, secret_key: Any, plaintext: Matrix) -> Any:
        return self._invoke(lambda: self.backend.encrypt(secret_key, plaintext))

    def evaluate_left_matrix(
        self,
        evaluation_key: Any,
        left_matrix: Matrix,
        ciphertext: Any,
        *,
        modulus: int,
    ) -> Any:
        if modulus != self.plaintext_modulus:
            raise ValueError("operation modulus does not match the bound FHE context")
        return self._invoke(
            lambda: self.backend.evaluate_left_matrix(
                evaluation_key,
                left_matrix,
                ciphertext,
                modulus=modulus,
            )
        )

    def decrypt(self, secret_key: Any, ciphertext: Any) -> Matrix:
        return self._invoke(lambda: self.backend.decrypt(secret_key, ciphertext))

    def logical_ciphertext_bytes(self, ciphertext: Any, *, modulus: int) -> int:
        if modulus != self.plaintext_modulus:
            raise ValueError("size modulus does not match the bound FHE context")
        return self._invoke(
            lambda: self.backend.logical_ciphertext_bytes(
                ciphertext, modulus=modulus
            )
        )


class FHEBackend(ABC):
    """Minimum matrix-delegation API needed by Figure 5 of the paper."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @property
    @abstractmethod
    def cryptographically_secure(self) -> bool: ...

    @abstractmethod
    def bind_context(
        self,
        *,
        context_digest_hex: str,
        profile_digest_hex: str,
        role: str,
        plaintext_modulus: int,
    ) -> str:
        """Bind this operation to a complete profile context and return its digest."""

    @abstractmethod
    def keygen(self) -> FHEKeyPair: ...

    @abstractmethod
    def encrypt(self, secret_key: Any, plaintext: Matrix) -> Any: ...

    @abstractmethod
    def evaluate_left_matrix(
        self,
        evaluation_key: Any,
        left_matrix: Matrix,
        ciphertext: Any,
        *,
        modulus: int,
    ) -> Any:
        """Return an encryption of ``left_matrix @ plaintext`` modulo the provided modulus."""

    @abstractmethod
    def decrypt(self, secret_key: Any, ciphertext: Any) -> Matrix: ...

    @abstractmethod
    def logical_ciphertext_bytes(self, ciphertext: Any, *, modulus: int) -> int: ...

    def _get_context_operation_lock(self) -> threading.RLock:
        """Return the per-backend lock, including for subclasses without super().__init__."""

        lock = getattr(self, "_fhe_context_operation_lock", None)
        if lock is not None:
            return lock
        with _LOCK_INITIALIZATION_GUARD:
            lock = getattr(self, "_fhe_context_operation_lock", None)
            if lock is None:
                lock = threading.RLock()
                object.__setattr__(self, "_fhe_context_operation_lock", lock)
            return lock

    def bound_context(
        self,
        *,
        context_digest_hex: str,
        profile_digest_hex: str,
        role: str,
        plaintext_modulus: int,
    ) -> BoundFHEContext:
        """Create an immutable handle that strongly binds every operation."""

        return BoundFHEContext(
            backend=self,
            context_digest_hex=context_digest_hex,
            profile_digest_hex=profile_digest_hex,
            role=role,
            plaintext_modulus=plaintext_modulus,
        )


class ProductionBackendUnavailable(RuntimeError):
    pass


class ProductionFHEBackend(FHEBackend):
    """Fail-closed placeholder for the future SEAL/HintlessPIR adapter."""

    @property
    def name(self) -> str:
        return "production-backend-not-integrated"

    @property
    def cryptographically_secure(self) -> bool:
        return False

    def _unavailable(self) -> None:
        raise ProductionBackendUnavailable(
            "No production FHE adapter is bundled. Integrate and audit the pinned "
            "Small-client vPIR/HintlessPIR C++ backend before using this profile."
        )

    def keygen(self) -> FHEKeyPair:
        self._unavailable()
        raise AssertionError("unreachable")

    def bind_context(
        self,
        *,
        context_digest_hex: str,
        profile_digest_hex: str,
        role: str,
        plaintext_modulus: int,
    ) -> str:
        self._unavailable()
        raise AssertionError("unreachable")

    def encrypt(self, secret_key: Any, plaintext: Matrix) -> Any:
        self._unavailable()

    def evaluate_left_matrix(
        self,
        evaluation_key: Any,
        left_matrix: Matrix,
        ciphertext: Any,
        *,
        modulus: int,
    ) -> Any:
        self._unavailable()

    def decrypt(self, secret_key: Any, ciphertext: Any) -> Matrix:
        self._unavailable()

    def logical_ciphertext_bytes(self, ciphertext: Any, *, modulus: int) -> int:
        self._unavailable()
        raise AssertionError("unreachable")
