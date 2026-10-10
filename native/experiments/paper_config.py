#!/usr/bin/env python3
"""Validate and expose the frozen paper-v1 experiment manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any


NATIVE_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_MANIFEST = NATIVE_ROOT / "manifests/paper-v1.json"
DEFAULT_CHECKSUM = NATIVE_ROOT / "manifests/paper-v1.sha256"
CANONICAL_PROFILES = (
    "dense",
    "negacyclic-main",
    "negacyclic-offline",
    "negacyclic-both",
)
FORMAL_SIZES = ("256mib", "512mib", "1gib", "2gib", "4gib")
ALL_SIZES = ("smoke",) + FORMAL_SIZES
FROZEN_CRYPTO = {
    "main_modulus": 4278255617,
    "offline_modulus": 18014398492704769,
    "plaintext_modulus": 256,
    "main_lwe_dimension": 1408,
    "offline_lwe_dimension": 2816,
    "main_ring_degree": 2048,
    "offline_ring_degree": 4096,
    "main_error_variance": 8,
}


class ManifestError(ValueError):
    """Raised when the frozen experiment manifest is inconsistent."""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _positive_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ManifestError(f"{label} must be a positive integer")
    return value


def load_manifest(
    path: Path = DEFAULT_MANIFEST,
    checksum_path: Path = DEFAULT_CHECKSUM,
    verify_checksum: bool = True,
) -> dict[str, Any]:
    try:
        manifest = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot load manifest {path}: {exc}") from exc
    if verify_checksum:
        try:
            expected = checksum_path.read_text(encoding="utf-8").split()[0]
        except (OSError, IndexError) as exc:
            raise ManifestError(f"cannot load manifest checksum {checksum_path}: {exc}") from exc
        actual = sha256_file(path)
        if actual != expected:
            raise ManifestError(
                f"frozen manifest checksum mismatch: expected {expected}, got {actual}"
            )
    validate_manifest(manifest)
    return manifest


def normalize_profile(manifest: dict[str, Any], profile: str) -> str:
    if profile in manifest["profiles"]:
        return profile
    aliases = {
        data["legacy_alias"]: canonical
        for canonical, data in manifest["profiles"].items()
    }
    try:
        return aliases[profile]
    except KeyError as exc:
        raise ManifestError(f"unknown preprocessing profile: {profile}") from exc


def validate_manifest(manifest: dict[str, Any]) -> None:
    if manifest.get("schema_version") != 1 or manifest.get("manifest_id") != "paper-v1":
        raise ManifestError("manifest must be schema 1 with manifest_id=paper-v1")
    threat = manifest.get("threat_model", {})
    if threat.get("hint_generation") != "honest" or threat.get("hint_authentication") != "external-to-this-poc":
        raise ManifestError("paper-v1 requires an honest externally authenticated hint")
    if threat.get("general_h") is not False:
        raise ManifestError("paper-v1 must not claim general-H support")

    crypto = manifest.get("cryptographic_parameters")
    if not isinstance(crypto, dict):
        raise ManifestError("cryptographic_parameters must be an object")
    for key, expected in FROZEN_CRYPTO.items():
        if crypto.get(key) != expected:
            raise ManifestError(f"frozen cryptographic parameter {key} must equal {expected}")
    fhe = crypto.get("fhe", {})
    expected_fhe = {
        "ring_degree": 4096,
        "moduli": [19988226643746817, 19988226643402753],
        "plaintext_modulus": 4278255617,
        "gadget_log_bases": [13, 14],
        "gadget_digits": 9,
        "error_variance": 8,
    }
    if fhe != expected_fhe:
        raise ManifestError("FHE parameters differ from the frozen paper-v1 profile")

    profiles = manifest.get("profiles")
    if not isinstance(profiles, dict) or tuple(profiles) != CANONICAL_PROFILES:
        raise ManifestError("profiles must contain the four canonical profiles in paper order")
    aliases = [profiles[name].get("legacy_alias") for name in CANONICAL_PROFILES]
    if len(set(aliases)) != len(aliases):
        raise ManifestError("legacy profile aliases must be unique")

    sizes = manifest.get("sizes")
    if not isinstance(sizes, dict) or set(sizes) != set(ALL_SIZES):
        raise ManifestError(
            "sizes must contain smoke, 256mib, 512mib, 1gib, 2gib, and 4gib"
        )
    expected_layouts = {
        "smoke": (2048, 2048, 1, 4 << 20),
        "256mib": (16384, 16384, 256, 256 << 20),
        "512mib": (32768, 16384, 8, 512 << 20),
        "1gib": (32768, 32768, 1, 1 << 30),
        "2gib": (65536, 32768, 32, 2 << 30),
        "4gib": (65536, 65536, 1, 4 << 30),
    }
    for name, (expected_rows, expected_columns, expected_stack, expected_bytes) in expected_layouts.items():
        size = sizes[name]
        rows = _positive_int(size.get("rows"), f"sizes.{name}.rows")
        columns = _positive_int(size.get("columns"), f"sizes.{name}.columns")
        record_bits = _positive_int(size.get("record_bits"), f"sizes.{name}.record_bits")
        stack = _positive_int(size.get("stack_cells"), f"sizes.{name}.stack_cells")
        logical_bytes = rows * columns * record_bits // 8
        if (rows, columns, stack, logical_bytes) != (
            expected_rows,
            expected_columns,
            expected_stack,
            expected_bytes,
        ):
            raise ManifestError(f"{name} does not match the frozen near-square layout")
        offline_degree = 2048 if name == "smoke" else crypto["offline_ring_degree"]
        if rows % offline_degree:
            raise ManifestError(f"{name} rows are incompatible with the offline ring degree")
        if columns % crypto["main_ring_degree"]:
            raise ManifestError(f"{name} columns are incompatible with the main ring degree")
        if size.get("main_pad_blocks") != columns // crypto["main_ring_degree"]:
            raise ManifestError(f"{name} main_pad_blocks is inconsistent")
        if size.get("offline_pad_blocks") != rows // offline_degree:
            raise ManifestError(f"{name} offline_pad_blocks is inconsistent")
        if _positive_int(size.get("minimum_memory_kib"), f"sizes.{name}.minimum_memory_kib") > _positive_int(
            size.get("recommended_memory_kib"), f"sizes.{name}.recommended_memory_kib"
        ):
            raise ManifestError(f"{name} minimum memory exceeds recommended memory")


def profile_values(manifest: dict[str, Any], size_name: str, profile_name: str) -> dict[str, str]:
    if size_name not in manifest["sizes"]:
        raise ManifestError(f"unknown database size: {size_name}")
    canonical = normalize_profile(manifest, profile_name)
    size = manifest["sizes"][size_name]
    profile = manifest["profiles"][canonical]
    crypto = manifest["cryptographic_parameters"]
    rows = size["rows"]
    stack = size["stack_cells"]
    main_structured = canonical in ("negacyclic-main", "negacyclic-both")
    offline_structured = canonical in ("negacyclic-offline", "negacyclic-both")
    offline_ring_degree = 2048 if size_name == "smoke" else crypto["offline_ring_degree"]
    return {
        "manifest_id": manifest["manifest_id"],
        "size": size_name,
        "profile": canonical,
        "legacy_alias": profile["legacy_alias"],
        "rows": str(rows),
        "columns": str(size["columns"]),
        "record_bits": str(size["record_bits"]),
        "stack_cells": str(stack),
        "logical_bytes": str(size["logical_bytes"]),
        "main_backend": profile["main_backend"],
        "offline_backend": profile["offline_backend"],
        "main_ring_degree": str(crypto["main_ring_degree"] if main_structured else 0),
        "offline_ring_degree": str(offline_ring_degree if offline_structured else 0),
        "main_pad_blocks": str(size["main_pad_blocks"] if main_structured else 0),
        "offline_pad_blocks": str(size["offline_pad_blocks"] if offline_structured else 0),
        "minimum_memory_kib": str(size["minimum_memory_kib"]),
        "recommended_memory_kib": str(size["recommended_memory_kib"]),
        "default_query_index": str(size["columns"] - 4),
        "proof_bound_B": str(rows * crypto["plaintext_modulus"]),
        "sis_infinity_bound": str(rows * (2 * crypto["plaintext_modulus"] - 1)),
        "main_security_status": (
            "screen-pass-conditional-on-paper-reduction" if main_structured else "baseline-lwe-screen-pass"
        ),
        "offline_security_status": (
            "screen-pass" if offline_structured else "baseline-lwe-screen-pass"
        ),
        "bfv_security_status": "screen-pass-minimal-margin",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--checksum", type=Path, default=DEFAULT_CHECKSUM)
    parser.add_argument("--skip-checksum", action="store_true")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("validate")
    emit = subparsers.add_parser("emit")
    emit.add_argument("--size", required=True)
    emit.add_argument("--profile", required=True)
    subparsers.add_parser("list")
    args = parser.parse_args()
    try:
        manifest = load_manifest(args.manifest, args.checksum, not args.skip_checksum)
        if args.command == "validate":
            print(f"manifest_id={manifest['manifest_id']}")
            print(f"manifest_sha256={sha256_file(args.manifest)}")
        elif args.command == "list":
            print("sizes=" + ",".join(FORMAL_SIZES))
            print("profiles=" + ",".join(CANONICAL_PROFILES))
        else:
            values = profile_values(manifest, args.size, args.profile)
            values["manifest_sha256"] = sha256_file(args.manifest)
            for key, value in values.items():
                print(f"{key}={value}")
    except ManifestError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
