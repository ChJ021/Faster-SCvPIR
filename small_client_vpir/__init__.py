"""Reparameterized Small-client vPIR engineering reference.

Nothing in this Python package is a production cryptographic implementation.
"""

from .benchmark import run_benchmark
from .parameters import PrimitiveContextParameters, ProtocolParameters, reference_parameters
from .protocol import (
    ClientProofState,
    CombinedOnlineRequest,
    CombinedOnlineResponse,
    QueryLimitExceeded,
    RetrievalResult,
    advertise_hint,
    answer_combined_online_query,
    answer_registration,
    begin_registration,
    begin_combined_online_query,
    finalize_registration,
    server_preprocess,
    setup,
    verify_combined_online_query,
)
from .reference_model import TransparentFHEBackend

__all__ = [
    "ClientProofState",
    "CombinedOnlineRequest",
    "CombinedOnlineResponse",
    "ProtocolParameters",
    "PrimitiveContextParameters",
    "QueryLimitExceeded",
    "RetrievalResult",
    "TransparentFHEBackend",
    "advertise_hint",
    "answer_combined_online_query",
    "answer_registration",
    "begin_registration",
    "begin_combined_online_query",
    "finalize_registration",
    "reference_parameters",
    "run_benchmark",
    "server_preprocess",
    "setup",
    "verify_combined_online_query",
]
