from __future__ import annotations

import argparse
import json
import random
from dataclasses import replace
from pathlib import Path
from typing import Sequence

from .benchmark import run_benchmark
from .parameters import ProtocolParameters, reference_parameters
from .protocol import (
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


def _print_json(value) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def run_demo() -> dict[str, object]:
    profile = reference_parameters()
    public = setup(profile)
    database = tuple(
        tuple((row * 5 + column * 3) % profile.p for column in range(profile.m))
        for row in range(profile.ell)
    )
    server = server_preprocess(public, database)
    registration_lhe = TransparentFHEBackend()
    hint_fhe = TransparentFHEBackend()
    prepared_registration = begin_registration(
        public, advertise_hint(server), registration_lhe, rng=random.Random(11)
    )
    client = finalize_registration(
        public,
        prepared_registration,
        answer_registration(
            public, server, prepared_registration.request, registration_lhe
        ),
        registration_lhe,
        rng=random.Random(12),
    )

    def prepare_combined(row: int, column: int, seed: int):
        prepared = begin_combined_online_query(
            public,
            client,
            hint_fhe,
            row=row,
            column=column,
            rng=random.Random(seed),
        )
        return prepared, answer_combined_online_query(
            public, server, prepared.request, hint_fhe
        )

    online, response = prepare_combined(2, 5, 20)
    honest = verify_combined_online_query(
        public, client, online, response, hint_fhe
    )
    tampered_online, tampered_response = prepare_combined(2, 5, 24)
    tampered_values = list(tampered_response.transformed_ciphertext)
    tampered_values[0] = (tampered_values[0] + 1) % profile.q
    tampered = verify_combined_online_query(
        public,
        client,
        tampered_online,
        replace(tampered_response, transformed_ciphertext=tuple(tampered_values)),
        hint_fhe,
    )

    return {
        "protocol": "Small-client vPIR general-bound Figure-5 reference",
        "execution_variant": "combined-online-security-baseline",
        "cryptographically_secure": False,
        "trusted_publisher_present": False,
        "honest_hint_assumed_for_parameters": False,
        "general_sis_beta": profile.general_sis_beta,
        "honest_result": honest.__dict__,
        "expected_value": database[2][5],
        "tampered_online_response_rejected": not tampered.accepted,
        "persistent_proof_rows": profile.gamma,
        "warning": "Transparent FHE reveals its plaintext; this is an algebraic control-flow model only.",
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Small-client vPIR engineering reference")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("demo", help="run the algebraic honest/malicious control-flow demo")
    benchmark = subparsers.add_parser("benchmark", help="emit the unified comparison JSON schema")
    benchmark.add_argument("--protocol", choices=("small-client", "via"), default="small-client")
    benchmark.add_argument("--rows", type=int, default=8)
    benchmark.add_argument("--columns", type=int, default=32)
    benchmark.add_argument("--queries", type=int, default=3)
    audit = subparsers.add_parser("audit-parameters", help="audit a JSON parameter profile")
    audit.add_argument("profile", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        _print_json(run_demo())
        return 0
    if args.command == "benchmark":
        _print_json(
            run_benchmark(
                protocol=args.protocol,
                rows=args.rows,
                columns=args.columns,
                queries=args.queries,
            )
        )
        return 0
    if args.command == "audit-parameters":
        profile = ProtocolParameters.load(args.profile)
        _print_json(profile.audit().to_dict())
        return 0 if profile.audit().production_ready else 2
    raise AssertionError("unreachable")
