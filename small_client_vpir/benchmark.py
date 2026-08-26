"""Unified benchmark schema for Small-client vPIR and the future VIA adapter."""

from __future__ import annotations

import random
import time
from typing import Any

from .algebra import matrix_logical_bytes
from .parameters import reference_parameters
from .protocol import (
    advertise_hint,
    answer_online_query,
    answer_query_preprocessing,
    answer_registration,
    begin_query_preprocessing,
    begin_registration,
    build_online_query,
    client_persistent_state_bytes,
    compressed_proof_state_bytes,
    finalize_query_preprocessing,
    finalize_registration,
    server_preprocess,
    setup,
    uncompressed_proof_state_bytes,
    verify_and_decode,
)
from .reference_model import TransparentFHEBackend


BENCHMARK_SCHEMA = "pir-comparison-reference-v0"

REFERENCE_BENCHMARK_GAPS = (
    "native serialized bytes",
    "latency p50/p95/p99 over repeated runs",
    "CPU time by phase",
    "measured peak RSS by phase",
    "throughput under fixed concurrency",
    "database pass count",
    "hardware/compiler/CPU-feature manifest",
)


def _timed(call):
    started = time.perf_counter()
    value = call()
    return value, time.perf_counter() - started


def _database(rows: int, columns: int, modulus: int) -> tuple[tuple[int, ...], ...]:
    return tuple(
        tuple((row * 131 + column * 17 + 3) % modulus for column in range(columns))
        for row in range(rows)
    )


def _logical_key_bytes(key: Any) -> int:
    """Best-effort size for the bundled reference key, never a wire claim."""

    return len(key) if isinstance(key, bytes) else 0


def _residue_bytes(modulus: int) -> int:
    """Bytes needed for a canonical residue in ``[0, modulus)``."""

    return max(1, ((modulus - 1).bit_length() + 7) // 8)


def run_small_client_benchmark(
    *, rows: int = 8, columns: int = 32, queries: int = 3
) -> dict[str, Any]:
    if rows <= 0 or columns <= 0 or queries <= 0:
        raise ValueError("rows, columns, and queries must be positive")
    profile = reference_parameters(
        rows=rows,
        columns=columns,
        lwe_dimension=min(16, columns),
        statistical_security_bits=16,
        protocol_variant="experimental-split-qlp-reference",
    )
    public, global_setup_seconds = _timed(lambda: setup(profile))
    database = _database(rows, columns, profile.p)
    registration_lhe = TransparentFHEBackend()
    hint_fhe = TransparentFHEBackend()

    server, database_preprocessing_seconds = _timed(lambda: server_preprocess(public, database))
    prepared_registration, registration_begin_client_seconds = _timed(
        lambda: begin_registration(
            public, advertise_hint(server), registration_lhe, rng=random.Random(1)
        )
    )
    registration_secret_key_bytes = _logical_key_bytes(
        prepared_registration.context.secret_key
    )
    registration_response, registration_server_seconds = _timed(
        lambda: answer_registration(
            public, server, prepared_registration.request, registration_lhe
        )
    )
    client, registration_finalize_client_seconds = _timed(
        lambda: finalize_registration(
            public,
            prepared_registration,
            registration_response,
            registration_lhe,
            rng=random.Random(2),
        )
    )

    query_prep_server_seconds = 0.0
    query_prep_begin_client_seconds = 0.0
    query_prep_finalize_client_seconds = 0.0
    online_server_seconds = 0.0
    online_build_client_seconds = 0.0
    online_verify_client_seconds = 0.0
    accepted = True
    query_prep_secret_key_bytes = 0
    prep_upload_bytes = prep_download_bytes = online_upload_bytes = online_download_bytes = 0
    for query_number in range(queries):
        prepared_prep, elapsed = _timed(
            lambda: begin_query_preprocessing(
                public, client, hint_fhe, rng=random.Random(100 + query_number)
            )
        )
        query_prep_secret_key_bytes = max(
            query_prep_secret_key_bytes,
            _logical_key_bytes(prepared_prep.context.fhe_secret_key),
        )
        query_prep_begin_client_seconds += elapsed
        prep_response, elapsed = _timed(
            lambda: answer_query_preprocessing(
                public, server, prepared_prep.request, hint_fhe
            )
        )
        query_prep_server_seconds += elapsed
        token, elapsed = _timed(
            lambda: finalize_query_preprocessing(
                public, client, prepared_prep, prep_response, hint_fhe
            )
        )
        query_prep_finalize_client_seconds += elapsed
        row, column = query_number % rows, (query_number * 7 + 1) % columns
        scalar_bytes = _residue_bytes(profile.q)
        token_bytes = (profile.m + profile.ell) * scalar_bytes + 64
        prepared_online, elapsed = _timed(
            lambda: build_online_query(
                public, token, row=row, column=column, rng=random.Random(200 + query_number)
            )
        )
        online_build_client_seconds += elapsed
        response, elapsed = _timed(
            lambda: answer_online_query(public, server, prepared_online.request)
        )
        online_server_seconds += elapsed
        result, elapsed = _timed(
            lambda: verify_and_decode(public, client, prepared_online, response)
        )
        online_verify_client_seconds += elapsed
        accepted &= result.accepted and result.value == database[row][column]
        prep_upload_bytes = hint_fhe.logical_ciphertext_bytes(
            prepared_prep.request.encrypted_lwe_secret, modulus=profile.q
        ) + _logical_key_bytes(prepared_prep.request.evaluation_key) + 32
        prep_download_bytes = hint_fhe.logical_ciphertext_bytes(
            prep_response.encrypted_hint_product, modulus=profile.q
        ) + 32
        online_upload_bytes = profile.m * scalar_bytes + 32
        online_download_bytes = profile.ell * scalar_bytes + 32

    scalar_q_bytes = _residue_bytes(profile.q)
    scalar_p_bytes = _residue_bytes(profile.p)
    registration_plaintext_modulus = profile.registration_lhe.plaintext_modulus
    if registration_plaintext_modulus is None:
        raise ValueError("registration LHE plaintext modulus is missing")
    hint_bytes = matrix_logical_bytes(server.hint, profile.q)
    public_matrix_bytes = matrix_logical_bytes(public.public_matrix, profile.q)
    registration_upload_bytes = registration_lhe.logical_ciphertext_bytes(
        prepared_registration.request.encrypted_challenge_transpose,
        modulus=registration_plaintext_modulus,
    ) + _logical_key_bytes(prepared_registration.request.evaluation_key) + 32
    registration_download_bytes = registration_lhe.logical_ciphertext_bytes(
        registration_response.encrypted_proof_transpose,
        modulus=registration_plaintext_modulus,
    ) + 32
    challenge_temporary_bytes = (profile.kappa * profile.ell + 7) // 8
    proof_temporary_bytes = (
        profile.kappa
        * profile.m
        * max(1, (profile.proof_norm_bound.bit_length() + 7) // 8)
    )
    compression_temporary_bytes = profile.gamma * profile.kappa * scalar_q_bytes
    registration_ephemeral_estimate = (
        hint_bytes
        + 32
        + challenge_temporary_bytes
        + proof_temporary_bytes
        + compression_temporary_bytes
        + client_persistent_state_bytes(public, client)
        + registration_upload_bytes
        + registration_download_bytes
        + registration_secret_key_bytes
    )
    query_ephemeral_estimate = (
        token_bytes
        + prep_upload_bytes
        + prep_download_bytes
        + online_upload_bytes
        + online_download_bytes
        + query_prep_secret_key_bytes
    )

    return {
        "schema": BENCHMARK_SCHEMA,
        "protocol": "small-client-vpir-general-bound",
        "status": "reference-model-only",
        "execution_variant": "experimental-split-qlp-reference",
        "comparison_ready": False,
        "measurement_gaps": list(REFERENCE_BENCHMARK_GAPS),
        "cryptographically_secure": False,
        "backends": {
            "registration_lhe": registration_lhe.name,
            "hint_fhe": hint_fhe.name,
        },
        "database": {
            "rows": rows,
            "columns": columns,
            "logical_bytes": rows * columns * scalar_p_bytes,
        },
        "parameters": {
            "p": profile.p,
            "q": profile.q,
            "ell": profile.ell,
            "m": profile.m,
            "n": profile.n,
            "kappa": profile.kappa,
            "gamma": profile.gamma,
            "B": profile.proof_norm_bound,
            "beta_general": profile.general_sis_beta,
            "max_queries_per_registration": profile.max_queries_per_registration,
            "max_registrations_per_client_lifetime": profile.max_registrations_per_client_lifetime,
            "protocol_variant": profile.protocol_variant,
            "query_distributions": {
                "secret": profile.query_secret_distribution,
                "error": profile.query_error_distribution,
            },
            "registration_lhe_scheme": profile.registration_lhe.scheme,
            "hint_fhe_scheme": profile.hint_fhe.scheme,
            "production_ready": profile.audit().production_ready,
        },
        "timings_seconds": {
            "global_setup": global_setup_seconds,
            "database_preprocessing": database_preprocessing_seconds,
            "client_registration_server": registration_server_seconds,
            "client_registration_begin_client": registration_begin_client_seconds,
            "client_registration_finalize_client": registration_finalize_client_seconds,
            "query_preprocessing_server_total": query_prep_server_seconds,
            "query_preprocessing_begin_client_total": query_prep_begin_client_seconds,
            "query_preprocessing_finalize_client_total": query_prep_finalize_client_seconds,
            "online_server_total": online_server_seconds,
            "online_build_client_total": online_build_client_seconds,
            "online_verify_client_total": online_verify_client_seconds,
        },
        "logical_bytes": {
            "public_matrix_seed": len(profile.matrix_seed),
            "public_matrix_expanded": public_matrix_bytes,
            "server_database": rows * columns * scalar_p_bytes,
            "server_hint": hint_bytes,
            "server_database_and_hint": rows * columns * scalar_p_bytes + hint_bytes,
            "client_persistent_compressed": client_persistent_state_bytes(public, client),
            "client_compressed_proof_payload": compressed_proof_state_bytes(public, client),
            "client_uncompressed_control": uncompressed_proof_state_bytes(public),
            "client_registration_server_to_client_hint": hint_bytes + 32,
            "client_registration_upload_ciphertext_and_evk": registration_upload_bytes,
            "client_registration_download_ciphertext": registration_download_bytes,
            "client_registration_secret_key_ephemeral": registration_secret_key_bytes,
            "client_registration_ephemeral_peak_estimate": registration_ephemeral_estimate,
            "query_preprocessing_upload_per_query": prep_upload_bytes,
            "query_preprocessing_download_per_query": prep_download_bytes,
            "query_preprocessing_secret_key_ephemeral": query_prep_secret_key_bytes,
            "query_token_before_consumption": token_bytes,
            "online_upload_per_query": online_upload_bytes,
            "online_download_per_query": online_download_bytes,
            "query_ephemeral_peak_estimate": query_ephemeral_estimate,
        },
        "queries": queries,
        "all_results_correct_and_accepted": accepted,
        "blocking_reason": None,
        "warning": "Python transparent-FHE timings and logical size estimates are not serialized C++/paper/production results; the split-QLP path has no approved external-feedback schedule and is not the Figure-5 security baseline.",
    }


def run_via_placeholder(*, rows: int, columns: int, queries: int) -> dict[str, Any]:
    return {
        "schema": BENCHMARK_SCHEMA,
        "protocol": "via-comparator",
        "status": "not-integrated",
        "execution_variant": "not-integrated",
        "comparison_ready": False,
        "measurement_gaps": list(REFERENCE_BENCHMARK_GAPS),
        "cryptographically_secure": False,
        "backends": None,
        "database": {"rows": rows, "columns": columns, "logical_bytes": None},
        "parameters": None,
        "queries": queries,
        "timings_seconds": None,
        "logical_bytes": None,
        "all_results_correct_and_accepted": None,
        "blocking_reason": "VIA is deliberately comparison-only in version 1; integrate its pinned native implementation before comparison.",
        "warning": "No VIA implementation or measurement is bundled; all result fields remain null.",
    }


def run_benchmark(
    *, protocol: str = "small-client", rows: int = 8, columns: int = 32, queries: int = 3
) -> dict[str, Any]:
    if protocol == "small-client":
        return run_small_client_benchmark(rows=rows, columns=columns, queries=queries)
    if protocol == "via":
        return run_via_placeholder(rows=rows, columns=columns, queries=queries)
    raise ValueError("protocol must be 'small-client' or 'via'")
