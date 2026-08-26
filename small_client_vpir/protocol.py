"""Executable algebraic model of reparameterized Small-client vPIR.

The control flow follows Rathee--Lee--Popa, Figure 5 and Section 3.4.  It
provides the original combined online request/response as the security
baseline and a separate split-QLP path for engineering experiments.  The
bundled FHE backend is transparent and all arithmetic is variable-time Python,
so this module is not a deployable cryptographic implementation.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence

from .algebra import (
    Matrix,
    Vector,
    as_matrix,
    as_vector,
    decode_plaintext,
    encode_plaintext,
    expand_public_matrix,
    infinity_norm,
    matmul,
    matvec,
    matrix_logical_bytes,
    shape,
    transpose,
    vector_add,
    vector_sub,
)
from .parameters import PrimitiveContextParameters, ProtocolParameters
from .primitives import BoundFHEContext, FHEBackend


UNIFORM_REJECTION_REASON = "verification_failed"


class RandomSource(Protocol):
    def randrange(self, stop: int) -> int: ...


class ProtocolError(Exception):
    pass


class RegistrationRejected(ProtocolError):
    pass


class QueryPreprocessingRejected(ProtocolError):
    pass


class TokenReuseError(ProtocolError):
    pass


class QueryLimitExceeded(ProtocolError):
    pass


@dataclass(frozen=True)
class PublicParameters:
    profile: ProtocolParameters
    public_matrix: Matrix
    profile_digest_hex: str


@dataclass(frozen=True)
class ServerDatabaseState:
    database: Matrix
    hint: Matrix
    profile_digest_hex: str


@dataclass(frozen=True)
class HintAdvertisement:
    hint: Matrix
    profile_digest_hex: str


@dataclass(frozen=True)
class RegistrationRequest:
    encrypted_challenge_transpose: Any
    evaluation_key: Any
    profile_digest_hex: str


@dataclass(frozen=True)
class RegistrationResponse:
    encrypted_proof_transpose: Any
    profile_digest_hex: str


@dataclass
class RegistrationContext:
    challenge: Matrix | None
    secret_key: Any
    advertised_hint: Matrix | None
    finalized: bool = False


@dataclass(frozen=True)
class PreparedRegistration:
    request: RegistrationRequest
    context: RegistrationContext


@dataclass
class ClientProofState:
    compressed_challenge: Matrix
    compressed_proof: Matrix
    profile_digest_hex: str
    hint_digest_hex: str
    state_fingerprint_hex: str
    queries_started: int = 0
    _query_counter_lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )


@dataclass(frozen=True)
class QueryPreprocessingRequest:
    encrypted_lwe_secret: Any
    evaluation_key: Any
    profile_digest_hex: str


@dataclass(frozen=True)
class QueryPreprocessingResponse:
    encrypted_hint_product: Any
    profile_digest_hex: str


@dataclass
class QueryPreprocessingContext:
    secret: Vector | None
    public_matrix_product: Vector | None
    fhe_secret_key: Any
    finalized: bool = False


@dataclass(frozen=True)
class PreparedQueryPreprocessing:
    request: QueryPreprocessingRequest
    context: QueryPreprocessingContext


@dataclass
class QueryToken:
    public_matrix_product: Vector
    hint_product: Vector
    profile_digest_hex: str
    state_fingerprint_hex: str
    consumed: bool = False
    _consume_lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )


@dataclass(frozen=True)
class OnlineQueryRequest:
    lwe_ciphertext: Vector
    profile_digest_hex: str


@dataclass
class OnlineQueryContext:
    requested_row: int
    requested_column: int
    lwe_ciphertext: Vector
    hint_product: Vector
    state_fingerprint_hex: str
    verified: bool = False
    _verify_lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )


@dataclass(frozen=True)
class PreparedOnlineQuery:
    request: OnlineQueryRequest
    context: OnlineQueryContext


@dataclass(frozen=True)
class OnlineResponse:
    transformed_ciphertext: Vector
    profile_digest_hex: str


@dataclass(frozen=True)
class RetrievalResult:
    accepted: bool
    value: int | None
    reason: str | None


@dataclass(frozen=True)
class CombinedOnlineRequest:
    """Figure-5 request: ``u``, ``Enc(s)`` and its evaluation key together."""

    lwe_ciphertext: Vector
    encrypted_lwe_secret: Any
    evaluation_key: Any
    profile_digest_hex: str


@dataclass(frozen=True)
class CombinedOnlineResponse:
    transformed_ciphertext: Vector
    encrypted_hint_product: Any
    profile_digest_hex: str


@dataclass
class CombinedOnlineContext:
    requested_row: int
    requested_column: int
    lwe_ciphertext: Vector
    public_matrix_product: Vector
    fhe_secret_key: Any
    state_fingerprint_hex: str
    verified: bool = False
    _verify_lock: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )


@dataclass(frozen=True)
class PreparedCombinedOnlineQuery:
    request: CombinedOnlineRequest
    context: CombinedOnlineContext


def _rng(source: RandomSource | None) -> RandomSource:
    return source if source is not None else secrets.SystemRandom()


def _reserve_query_budget(
    client: ClientProofState, profile: ProtocolParameters
) -> None:
    """Atomically reserve one query in this process only."""

    # The native implementation must persist this counter crash-consistently
    # before emitting a request.  A Python lock cannot prevent rollback or
    # copying an older serialized state.
    with client._query_counter_lock:
        if client.queries_started >= profile.max_queries_per_registration:
            raise QueryLimitExceeded(
                "the registered proof reached its parameterized maximum query count"
            )
        client.queries_started += 1


def _require_split_qlp_variant(public: PublicParameters) -> None:
    if public.profile.protocol_variant != "experimental-split-qlp-reference":
        raise ValueError(
            "split QLP is disabled by this profile; version-1 production certificates permit only figure5-combined"
        )


def _require_combined_variant(public: PublicParameters) -> None:
    if public.profile.protocol_variant != "figure5-combined":
        raise ValueError(
            "combined Figure-5 online mode is disabled by this profile"
        )


def _bind_backend_context(
    backend: FHEBackend,
    context: PrimitiveContextParameters,
    profile_digest_hex: str,
) -> BoundFHEContext:
    if context.plaintext_modulus is None:
        raise ValueError("primitive context has no plaintext modulus")
    bound = backend.bound_context(
        context_digest_hex=context.digest_hex,
        profile_digest_hex=profile_digest_hex,
        role=context.role,
        plaintext_modulus=context.plaintext_modulus,
    )
    bound.validate()
    return bound


def _matrix_digest(matrix: Matrix, modulus: int) -> str:
    width = max(1, (modulus.bit_length() + 7) // 8)
    digest = hashlib.sha256(b"SCVPIR-HINT-v1\x00")
    rows, columns = shape(matrix)
    digest.update(rows.to_bytes(8, "big"))
    digest.update(columns.to_bytes(8, "big"))
    for row in matrix:
        for value in row:
            digest.update((value % modulus).to_bytes(width, "big"))
    return digest.hexdigest()


def _proof_state_fingerprint(
    *,
    compressed_challenge: Matrix,
    compressed_proof: Matrix,
    profile_digest_hex: str,
    hint_digest_hex: str,
    modulus: int,
) -> str:
    digest = hashlib.sha256(b"SCVPIR-CLIENT-PROOF-STATE-v1\x00")
    digest.update(bytes.fromhex(profile_digest_hex))
    digest.update(bytes.fromhex(hint_digest_hex))
    digest.update(bytes.fromhex(_matrix_digest(compressed_challenge, modulus)))
    digest.update(bytes.fromhex(_matrix_digest(compressed_proof, modulus)))
    return digest.hexdigest()


def setup(profile: ProtocolParameters) -> PublicParameters:
    profile.require_executable_math()
    if profile.profile_kind != "reference-only":
        raise ValueError(
            "the Python algebraic model refuses production-candidate profiles; use the audited native backend"
        )
    if (
        profile.query_secret_distribution != "uniform-ternary-reference"
        or profile.query_error_distribution != "uniform-ternary-reference"
    ):
        raise ValueError("the bundled reference sampler only implements uniform ternary s and e")
    if profile.error_sigma != 1.0:
        raise ValueError(
            "the uniform-ternary reference sampler is bound to the conservative Hoeffding subgaussian parameter 1.0"
        )
    public_matrix = expand_public_matrix(profile.matrix_seed, profile.m, profile.n, profile.q)
    return PublicParameters(profile, public_matrix, profile.digest_hex)


def server_preprocess(public: PublicParameters, database: Sequence[Sequence[int]]) -> ServerDatabaseState:
    checked = as_matrix(database)
    if shape(checked) != (public.profile.ell, public.profile.m):
        raise ValueError("database matrix shape does not match the parameter profile")
    if any(not 0 <= value < public.profile.p for row in checked for value in row):
        raise ValueError("database entries must lie in Z_p")
    hint = matmul(checked, public.public_matrix, modulus=public.profile.q)
    return ServerDatabaseState(checked, hint, public.profile_digest_hex)


def advertise_hint(server: ServerDatabaseState) -> HintAdvertisement:
    return HintAdvertisement(server.hint, server.profile_digest_hex)


def begin_registration(
    public: PublicParameters,
    advertisement: HintAdvertisement,
    registration_lhe: FHEBackend,
    *,
    rng: RandomSource | None = None,
) -> PreparedRegistration:
    profile = public.profile
    bound_registration_lhe = _bind_backend_context(
        registration_lhe, profile.registration_lhe, public.profile_digest_hex
    )
    if advertisement.profile_digest_hex != public.profile_digest_hex:
        raise ValueError("hint was generated under a different parameter profile")
    if shape(advertisement.hint) != (profile.ell, profile.n):
        raise ValueError("advertised hint has an invalid shape")
    if any(not 0 <= value < profile.q for row in advertisement.hint for value in row):
        raise ValueError("advertised hint contains a non-canonical residue")
    source = _rng(rng)
    challenge = tuple(
        tuple(source.randrange(2) for _ in range(profile.ell))
        for _ in range(profile.kappa)
    )
    keys = bound_registration_lhe.keygen()
    encrypted = bound_registration_lhe.encrypt(
        keys.secret_key, transpose(challenge)
    )
    return PreparedRegistration(
        RegistrationRequest(encrypted, keys.evaluation_key, public.profile_digest_hex),
        RegistrationContext(challenge, keys.secret_key, advertisement.hint),
    )


def answer_registration(
    public: PublicParameters,
    server: ServerDatabaseState,
    request: RegistrationRequest,
    registration_lhe: FHEBackend,
) -> RegistrationResponse:
    bound_registration_lhe = _bind_backend_context(
        registration_lhe,
        public.profile.registration_lhe,
        public.profile_digest_hex,
    )
    if request.profile_digest_hex != public.profile_digest_hex or server.profile_digest_hex != public.profile_digest_hex:
        raise ValueError("registration state belongs to a different parameter profile")
    registration_plaintext_modulus = public.profile.registration_lhe.plaintext_modulus
    if registration_plaintext_modulus is None:
        raise ValueError("registration LHE plaintext modulus is not configured")
    encrypted_proof_transpose = bound_registration_lhe.evaluate_left_matrix(
        request.evaluation_key,
        transpose(server.database),
        request.encrypted_challenge_transpose,
        modulus=registration_plaintext_modulus,
    )
    return RegistrationResponse(encrypted_proof_transpose, public.profile_digest_hex)


def finalize_registration(
    public: PublicParameters,
    prepared: PreparedRegistration,
    response: RegistrationResponse,
    registration_lhe: FHEBackend,
    *,
    rng: RandomSource | None = None,
) -> ClientProofState:
    profile = public.profile
    bound_registration_lhe = _bind_backend_context(
        registration_lhe, profile.registration_lhe, public.profile_digest_hex
    )
    context = prepared.context
    if context.finalized:
        raise RegistrationRejected(UNIFORM_REJECTION_REASON)
    try:
        if context.challenge is None or context.advertised_hint is None or context.secret_key is None:
            raise ValueError("registration context was already cleared")
        if response.profile_digest_hex != public.profile_digest_hex:
            raise ValueError("registration response profile mismatch")
        proof_transpose = bound_registration_lhe.decrypt(
            context.secret_key, response.encrypted_proof_transpose
        )
        proof = transpose(as_matrix(proof_transpose))
        if shape(proof) != (profile.kappa, profile.m):
            raise ValueError("proof has an invalid shape")
        registration_plaintext_modulus = profile.registration_lhe.plaintext_modulus
        if registration_plaintext_modulus is None:
            raise ValueError("registration LHE plaintext modulus is not configured")
        # Figure 5 treats Z as an integer matrix.  In the byte/Z_p profile,
        # decode registration-LHE residues canonically from [0,t_reg), where
        # t_reg > ell*(p-1); only later embed Z into Z_q for commitment checks.
        if any(
            not 0 <= value < registration_plaintext_modulus
            for row in proof
            for value in row
        ):
            raise ValueError("registration proof has a non-canonical plaintext residue")
        # This check is security-critical and must happen before compression.
        if infinity_norm(proof) > profile.proof_norm_bound:
            raise ValueError("uncompressed proof exceeds B")
        source = _rng(rng)
        compression = tuple(
            tuple(source.randrange(profile.q) for _ in range(profile.kappa))
            for _ in range(profile.gamma)
        )
        compressed_proof = matmul(compression, proof, modulus=profile.q)
        compressed_challenge = matmul(compression, context.challenge, modulus=profile.q)
        left = matmul(compressed_proof, public.public_matrix, modulus=profile.q)
        right = matmul(compressed_challenge, context.advertised_hint, modulus=profile.q)
        if left != right:
            raise ValueError("compressed proof equation Z'A=C'H failed")
        hint_digest_hex = _matrix_digest(context.advertised_hint, profile.q)
        state_fingerprint_hex = _proof_state_fingerprint(
            compressed_challenge=compressed_challenge,
            compressed_proof=compressed_proof,
            profile_digest_hex=public.profile_digest_hex,
            hint_digest_hex=hint_digest_hex,
            modulus=profile.q,
        )
        return ClientProofState(
            compressed_challenge=compressed_challenge,
            compressed_proof=compressed_proof,
            profile_digest_hex=public.profile_digest_hex,
            hint_digest_hex=hint_digest_hex,
            state_fingerprint_hex=state_fingerprint_hex,
        )
    except Exception as exc:
        raise RegistrationRejected(UNIFORM_REJECTION_REASON) from exc
    finally:
        # Logical invalidation only. Python cannot guarantee physical zeroization.
        context.challenge = None
        context.secret_key = None
        context.advertised_hint = None
        context.finalized = True


def begin_query_preprocessing(
    public: PublicParameters,
    client: ClientProofState,
    hint_fhe: FHEBackend,
    *,
    rng: RandomSource | None = None,
) -> PreparedQueryPreprocessing:
    _require_split_qlp_variant(public)
    profile = public.profile
    bound_hint_fhe = _bind_backend_context(
        hint_fhe, profile.hint_fhe, public.profile_digest_hex
    )
    if client.profile_digest_hex != public.profile_digest_hex:
        raise ValueError("client state belongs to a different parameter profile")
    _reserve_query_budget(client, profile)
    source = _rng(rng)
    secret = tuple(source.randrange(3) - 1 for _ in range(profile.n))
    public_matrix_product = matvec(public.public_matrix, secret, modulus=profile.q)
    keys = bound_hint_fhe.keygen()
    encrypted_secret = bound_hint_fhe.encrypt(
        keys.secret_key, tuple((value,) for value in secret)
    )
    prepared = PreparedQueryPreprocessing(
        QueryPreprocessingRequest(encrypted_secret, keys.evaluation_key, public.profile_digest_hex),
        QueryPreprocessingContext(secret, public_matrix_product, keys.secret_key),
    )
    return prepared


def answer_query_preprocessing(
    public: PublicParameters,
    server: ServerDatabaseState,
    request: QueryPreprocessingRequest,
    hint_fhe: FHEBackend,
) -> QueryPreprocessingResponse:
    _require_split_qlp_variant(public)
    bound_hint_fhe = _bind_backend_context(
        hint_fhe, public.profile.hint_fhe, public.profile_digest_hex
    )
    if request.profile_digest_hex != public.profile_digest_hex or server.profile_digest_hex != public.profile_digest_hex:
        raise ValueError("query preprocessing profile mismatch")
    encrypted_hint_product = bound_hint_fhe.evaluate_left_matrix(
        request.evaluation_key,
        server.hint,
        request.encrypted_lwe_secret,
        modulus=public.profile.q,
    )
    return QueryPreprocessingResponse(encrypted_hint_product, public.profile_digest_hex)


def finalize_query_preprocessing(
    public: PublicParameters,
    client: ClientProofState,
    prepared: PreparedQueryPreprocessing,
    response: QueryPreprocessingResponse,
    hint_fhe: FHEBackend,
) -> QueryToken:
    _require_split_qlp_variant(public)
    profile = public.profile
    bound_hint_fhe = _bind_backend_context(
        hint_fhe, profile.hint_fhe, public.profile_digest_hex
    )
    context = prepared.context
    if context.finalized:
        raise QueryPreprocessingRejected(UNIFORM_REJECTION_REASON)
    try:
        if (
            context.secret is None
            or context.public_matrix_product is None
            or context.fhe_secret_key is None
        ):
            raise ValueError("query preprocessing context was already cleared")
        if response.profile_digest_hex != public.profile_digest_hex:
            raise ValueError("query preprocessing response profile mismatch")
        plaintext = as_matrix(
            bound_hint_fhe.decrypt(
                context.fhe_secret_key, response.encrypted_hint_product
            )
        )
        if shape(plaintext) != (profile.ell, 1):
            raise ValueError("hint product has an invalid shape")
        if any(not 0 <= value < profile.q for row in plaintext for value in row):
            raise ValueError("hint product contains a non-canonical residue")
        hint_product = tuple(row[0] % profile.q for row in plaintext)
        left = matvec(client.compressed_proof, context.public_matrix_product, modulus=profile.q)
        right = matvec(client.compressed_challenge, hint_product, modulus=profile.q)
        if left != right:
            raise ValueError("query preprocessing equation Z'As=C'w failed")
        return QueryToken(
            public_matrix_product=context.public_matrix_product,
            hint_product=hint_product,
            profile_digest_hex=public.profile_digest_hex,
            state_fingerprint_hex=client.state_fingerprint_hex,
        )
    except Exception as exc:
        raise QueryPreprocessingRejected(UNIFORM_REJECTION_REASON) from exc
    finally:
        context.secret = None
        context.public_matrix_product = None
        context.fhe_secret_key = None
        context.finalized = True


def build_online_query(
    public: PublicParameters,
    token: QueryToken,
    *,
    row: int,
    column: int,
    rng: RandomSource | None = None,
) -> PreparedOnlineQuery:
    _require_split_qlp_variant(public)
    profile = public.profile
    # Reserve and consume atomically in this process.  A production token must
    # use a persisted unused->reserved->spent state machine; this lock alone
    # does not survive process restart or state rollback.
    with token._consume_lock:
        if token.profile_digest_hex != public.profile_digest_hex:
            raise ValueError("query token belongs to a different parameter profile")
        if token.consumed:
            raise TokenReuseError("query preprocessing tokens are consumable and single-use")
        if not 0 <= row < profile.ell or not 0 <= column < profile.m:
            raise IndexError("requested database cell is out of range")
        if not token.public_matrix_product or not token.hint_product:
            raise TokenReuseError("query token material was cleared")
        source = _rng(rng)
        error = tuple(source.randrange(3) - 1 for _ in range(profile.m))
        encoded_selector = tuple(
            encode_plaintext(1 if index == column else 0, profile.p, profile.q)
            for index in range(profile.m)
        )
        lwe_ciphertext = vector_add(
            token.public_matrix_product,
            error,
            encoded_selector,
            modulus=profile.q,
        )
        prepared = PreparedOnlineQuery(
            OnlineQueryRequest(lwe_ciphertext, public.profile_digest_hex),
            OnlineQueryContext(
                row,
                column,
                lwe_ciphertext,
                token.hint_product,
                token.state_fingerprint_hex,
            ),
        )
        token.public_matrix_product = ()
        token.hint_product = ()
        token.consumed = True
        return prepared


def answer_online_query(
    public: PublicParameters,
    server: ServerDatabaseState,
    request: OnlineQueryRequest,
) -> OnlineResponse:
    _require_split_qlp_variant(public)
    if request.profile_digest_hex != public.profile_digest_hex or server.profile_digest_hex != public.profile_digest_hex:
        raise ValueError("online query profile mismatch")
    ciphertext = as_vector(request.lwe_ciphertext)
    if len(ciphertext) != public.profile.m:
        raise ValueError("online LWE ciphertext has an invalid shape")
    if any(not 0 <= value < public.profile.q for value in ciphertext):
        raise ValueError("online LWE ciphertext contains a non-canonical residue")
    transformed = matvec(server.database, ciphertext, modulus=public.profile.q)
    return OnlineResponse(transformed, public.profile_digest_hex)


def verify_and_decode(
    public: PublicParameters,
    client: ClientProofState,
    prepared: PreparedOnlineQuery,
    response: Any,
) -> RetrievalResult:
    _require_split_qlp_variant(public)
    profile = public.profile
    context = prepared.context
    # Claim the only externally reportable verification outcome before any
    # decryption.  Native code must persist an equivalent pending->spent
    # transition if a context can survive process restart.
    with context._verify_lock:
        if context.verified:
            return RetrievalResult(False, None, UNIFORM_REJECTION_REASON)
        context.verified = True
    try:
        if client.profile_digest_hex != public.profile_digest_hex:
            raise ValueError("client proof profile mismatch")
        if context.state_fingerprint_hex != client.state_fingerprint_hex:
            raise ValueError("query token belongs to a different registered proof state")
        if not isinstance(response, OnlineResponse):
            raise TypeError("online response has an invalid type")
        if response.profile_digest_hex != public.profile_digest_hex:
            raise ValueError("online response profile mismatch")
        transformed = as_vector(response.transformed_ciphertext)
        if len(transformed) != profile.ell:
            raise ValueError("online response has an invalid shape")
        if any(not 0 <= value < profile.q for value in transformed):
            raise ValueError("online response contains a non-canonical residue")
        left = matvec(client.compressed_proof, context.lwe_ciphertext, modulus=profile.q)
        right = matvec(client.compressed_challenge, transformed, modulus=profile.q)
        if left != right:
            raise ValueError("online equation Z'u=C'v failed")
        encoded_result = vector_sub(transformed, context.hint_product, modulus=profile.q)
        decoded = tuple(decode_plaintext(value, profile.p, profile.q) for value in encoded_result)
        return RetrievalResult(True, decoded[context.requested_row], None)
    except Exception:
        return RetrievalResult(False, None, UNIFORM_REJECTION_REASON)
    finally:
        context.lwe_ciphertext = ()
        context.hint_product = ()
        context.requested_row = -1
        context.requested_column = -1
        context.state_fingerprint_hex = ""


def begin_combined_online_query(
    public: PublicParameters,
    client: ClientProofState,
    hint_fhe: FHEBackend,
    *,
    row: int,
    column: int,
    rng: RandomSource | None = None,
) -> PreparedCombinedOnlineQuery:
    """Build the original Figure-5 request with one externally visible round."""

    _require_combined_variant(public)
    profile = public.profile
    bound_hint_fhe = _bind_backend_context(
        hint_fhe, profile.hint_fhe, public.profile_digest_hex
    )
    if client.profile_digest_hex != public.profile_digest_hex:
        raise ValueError("client state belongs to a different parameter profile")
    if not 0 <= row < profile.ell or not 0 <= column < profile.m:
        raise IndexError("requested database cell is out of range")
    _reserve_query_budget(client, profile)
    source = _rng(rng)
    secret = tuple(source.randrange(3) - 1 for _ in range(profile.n))
    error = tuple(source.randrange(3) - 1 for _ in range(profile.m))
    public_matrix_product = matvec(
        public.public_matrix, secret, modulus=profile.q
    )
    encoded_selector = tuple(
        encode_plaintext(1 if index == column else 0, profile.p, profile.q)
        for index in range(profile.m)
    )
    lwe_ciphertext = vector_add(
        public_matrix_product, error, encoded_selector, modulus=profile.q
    )
    keys = bound_hint_fhe.keygen()
    encrypted_secret = bound_hint_fhe.encrypt(
        keys.secret_key, tuple((value,) for value in secret)
    )
    return PreparedCombinedOnlineQuery(
        CombinedOnlineRequest(
            lwe_ciphertext,
            encrypted_secret,
            keys.evaluation_key,
            public.profile_digest_hex,
        ),
        CombinedOnlineContext(
            row,
            column,
            lwe_ciphertext,
            public_matrix_product,
            keys.secret_key,
            client.state_fingerprint_hex,
        ),
    )


def answer_combined_online_query(
    public: PublicParameters,
    server: ServerDatabaseState,
    request: CombinedOnlineRequest,
    hint_fhe: FHEBackend,
) -> CombinedOnlineResponse:
    """Return ``v=D*u`` and ``Enc(H*s)`` in the same server response."""

    _require_combined_variant(public)
    bound_hint_fhe = _bind_backend_context(
        hint_fhe, public.profile.hint_fhe, public.profile_digest_hex
    )
    if (
        request.profile_digest_hex != public.profile_digest_hex
        or server.profile_digest_hex != public.profile_digest_hex
    ):
        raise ValueError("combined online query profile mismatch")
    ciphertext = as_vector(request.lwe_ciphertext)
    if len(ciphertext) != public.profile.m:
        raise ValueError("combined online LWE ciphertext has an invalid shape")
    if any(not 0 <= value < public.profile.q for value in ciphertext):
        raise ValueError("combined online query contains a non-canonical residue")
    transformed = matvec(server.database, ciphertext, modulus=public.profile.q)
    encrypted_hint_product = bound_hint_fhe.evaluate_left_matrix(
        request.evaluation_key,
        server.hint,
        request.encrypted_lwe_secret,
        modulus=public.profile.q,
    )
    return CombinedOnlineResponse(
        transformed, encrypted_hint_product, public.profile_digest_hex
    )


def verify_combined_online_query(
    public: PublicParameters,
    client: ClientProofState,
    prepared: PreparedCombinedOnlineQuery,
    response: Any,
    hint_fhe: FHEBackend,
) -> RetrievalResult:
    """Perform both Figure-5 equations and expose one local accept/reject."""

    _require_combined_variant(public)
    profile = public.profile
    bound_hint_fhe = _bind_backend_context(
        hint_fhe, profile.hint_fhe, public.profile_digest_hex
    )
    context = prepared.context
    # Atomically claim the single externally reportable verification result.
    with context._verify_lock:
        if context.verified:
            return RetrievalResult(False, None, UNIFORM_REJECTION_REASON)
        context.verified = True
    try:
        if client.profile_digest_hex != public.profile_digest_hex:
            raise ValueError("client proof profile mismatch")
        if context.state_fingerprint_hex != client.state_fingerprint_hex:
            raise ValueError("combined query belongs to another proof state")
        if context.fhe_secret_key is None:
            raise ValueError("combined online secret was already cleared")
        if not isinstance(response, CombinedOnlineResponse):
            raise TypeError("combined online response has an invalid type")
        if response.profile_digest_hex != public.profile_digest_hex:
            raise ValueError("combined online response profile mismatch")
        transformed = as_vector(response.transformed_ciphertext)
        if len(transformed) != profile.ell:
            raise ValueError("combined online response has an invalid shape")
        if any(not 0 <= value < profile.q for value in transformed):
            raise ValueError("combined online response has a non-canonical residue")
        plaintext = as_matrix(
            bound_hint_fhe.decrypt(
                context.fhe_secret_key, response.encrypted_hint_product
            )
        )
        if shape(plaintext) != (profile.ell, 1):
            raise ValueError("combined hint product has an invalid shape")
        if any(not 0 <= value < profile.q for row in plaintext for value in row):
            raise ValueError("combined hint product has a non-canonical residue")
        hint_product = tuple(row[0] for row in plaintext)
        if matvec(
            client.compressed_proof,
            context.public_matrix_product,
            modulus=profile.q,
        ) != matvec(
            client.compressed_challenge, hint_product, modulus=profile.q
        ):
            raise ValueError("combined equation Z'As=C'w failed")
        if matvec(
            client.compressed_proof,
            context.lwe_ciphertext,
            modulus=profile.q,
        ) != matvec(
            client.compressed_challenge, transformed, modulus=profile.q
        ):
            raise ValueError("combined equation Z'u=C'v failed")
        encoded_result = vector_sub(transformed, hint_product, modulus=profile.q)
        decoded = tuple(
            decode_plaintext(value, profile.p, profile.q)
            for value in encoded_result
        )
        return RetrievalResult(True, decoded[context.requested_row], None)
    except Exception:
        return RetrievalResult(False, None, UNIFORM_REJECTION_REASON)
    finally:
        context.lwe_ciphertext = ()
        context.public_matrix_product = ()
        context.fhe_secret_key = None
        context.requested_row = -1
        context.requested_column = -1
        context.state_fingerprint_hex = ""


def client_persistent_state_bytes(public: PublicParameters, client: ClientProofState) -> int:
    # The hint digest is operational binding only; it authenticates no external DB.
    return compressed_proof_state_bytes(public, client) + 104


def compressed_proof_state_bytes(
    public: PublicParameters, client: ClientProofState
) -> int:
    """Return only the ``(C', Z')`` matrix payload, excluding fixed metadata."""

    return matrix_logical_bytes(
        client.compressed_challenge, public.profile.q
    ) + matrix_logical_bytes(client.compressed_proof, public.profile.q)


def uncompressed_proof_state_bytes(public: PublicParameters) -> int:
    profile = public.profile
    proof_bits = profile.kappa * profile.m * max(1, profile.proof_norm_bound.bit_length())
    challenge_bits = profile.kappa * profile.ell
    return (proof_bits + challenge_bits + 7) // 8
