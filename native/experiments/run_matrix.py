#!/usr/bin/env python3
"""Run a deterministic balanced paper-v1 experiment matrix."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import random
import subprocess
import sys
from pathlib import Path
from typing import Any

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from native.experiments.paper_config import (  # type: ignore
        CANONICAL_PROFILES,
        FORMAL_SIZES,
        DEFAULT_CHECKSUM,
        DEFAULT_MANIFEST,
        ManifestError,
        load_manifest,
        normalize_profile,
        sha256_file,
    )
else:
    from .paper_config import (
        CANONICAL_PROFILES,
        FORMAL_SIZES,
        DEFAULT_CHECKSUM,
        DEFAULT_MANIFEST,
        ManifestError,
        load_manifest,
        normalize_profile,
        sha256_file,
    )


PROJECT_ROOT = Path(__file__).resolve().parents[2]
RUNNER = PROJECT_ROOT / "native/scripts/build-run-paper.sh"
SCHEDULE_ROOT = PROJECT_ROOT / "native/logs/paper-v1/schedules"


def comma_list(raw: str, allowed: tuple[str, ...], label: str) -> list[str]:
    values = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = sorted(set(values) - set(allowed))
    if not values or unknown or len(values) != len(set(values)):
        detail = f"; unknown: {', '.join(unknown)}" if unknown else ""
        raise ValueError(f"invalid {label} list{detail}")
    return values


def balanced_rows(items: list[str]) -> list[list[str]]:
    if len(items) == 1:
        return [items]
    indices: list[int] = []
    low, high = 0, len(items) - 1
    while low <= high:
        indices.append(low)
        low += 1
        if low <= high:
            indices.append(high)
            high -= 1
    first = [items[index] for index in indices]
    return [first[offset:] + first[:offset] for offset in range(len(items))]


def deterministic_query(size: dict[str, Any], seed: int, size_name: str, repetition: int) -> int:
    material = f"paper-v1:{seed}:{size_name}:{repetition}".encode("ascii")
    digest = hashlib.sha256(material).digest()
    row_groups = size["rows"] // size["stack_cells"]
    group = int.from_bytes(digest[:8], "big") % row_groups
    column = int.from_bytes(digest[8:16], "big") % size["columns"]
    row = group * size["stack_cells"]
    return row * size["columns"] + column


def atomic_json(path: Path, payload: dict[str, Any], create: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if create and path.exists():
        raise FileExistsError(f"schedule already exists: {path}")
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def build_schedule(
    manifest: dict[str, Any],
    sizes: list[str],
    profiles: list[str],
    repetitions: int,
    seed: int,
    session_id: str,
    manifest_sha256: str,
) -> dict[str, Any]:
    rng = random.Random(seed)
    shuffled_sizes = list(sizes)
    shuffled_profiles = list(profiles)
    rng.shuffle(shuffled_sizes)
    rng.shuffle(shuffled_profiles)
    profile_rows = balanced_rows(shuffled_profiles)
    cells: list[dict[str, Any]] = []
    for repetition in range(repetitions):
        for size_offset, size_name in enumerate(shuffled_sizes):
            order = profile_rows[(repetition + size_offset) % len(profile_rows)]
            query_index = deterministic_query(
                manifest["sizes"][size_name], seed, size_name, repetition
            )
            for order_index, profile in enumerate(order):
                cells.append(
                    {
                        "repetition": repetition + 1,
                        "size": size_name,
                        "profile": profile,
                        "order_index": order_index + 1,
                        "query_index": query_index,
                        "run_id": f"{session_id}-r{repetition + 1}-{size_name}-{profile}",
                        "status": "pending",
                    }
                )
    return {
        "schema_version": 1,
        "manifest_id": manifest["manifest_id"],
        "manifest_sha256": manifest_sha256,
        "session_id": session_id,
        "created_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "sizes": sizes,
        "profiles": profiles,
        "repetitions": repetitions,
        "order_seed": seed,
        "order_design": "seeded-permutation-balanced-latin-rotation",
        "cells": cells,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sizes", default=",".join(FORMAL_SIZES))
    parser.add_argument("--profiles", default=",".join(CANONICAL_PROFILES))
    parser.add_argument("--repetitions", type=int)
    parser.add_argument("--order-seed", type=int)
    parser.add_argument("--session-id")
    parser.add_argument("--cpu-set")
    parser.add_argument("--resume", type=Path)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--allow-low-memory", action="store_true")
    parser.add_argument("--allow-unstable-cpu", action="store_true")
    args = parser.parse_args()

    try:
        if not args.dry_run and not args.cpu_set:
            raise ValueError("formal matrix execution requires --cpu-set")
        manifest = load_manifest(DEFAULT_MANIFEST, DEFAULT_CHECKSUM)
        manifest_sha256 = sha256_file(DEFAULT_MANIFEST)
        if args.resume:
            schedule_path = args.resume.resolve()
            schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
            if (
                schedule.get("manifest_id") != manifest["manifest_id"]
                or schedule.get("manifest_sha256") != manifest_sha256
            ):
                raise ValueError("resume schedule uses a different frozen manifest")
        else:
            if args.repetitions is None or args.repetitions <= 0:
                raise ValueError("--repetitions must be a positive integer")
            if args.order_seed is None:
                raise ValueError("--order-seed is required")
            sizes = comma_list(args.sizes, FORMAL_SIZES, "sizes")
            raw_profiles = [item.strip() for item in args.profiles.split(",") if item.strip()]
            profiles = [normalize_profile(manifest, item) for item in raw_profiles]
            if not profiles or len(profiles) != len(set(profiles)):
                raise ValueError("profiles must be a non-empty unique list")
            session_id = args.session_id or dt.datetime.now(dt.timezone.utc).strftime(
                "matrix-%Y%m%dT%H%M%SZ"
            )
            if not all(character.isalnum() or character in "._-" for character in session_id):
                raise ValueError("session id contains unsupported characters")
            schedule = build_schedule(
                manifest,
                sizes,
                profiles,
                args.repetitions,
                args.order_seed,
                session_id,
                manifest_sha256,
            )
            schedule_path = SCHEDULE_ROOT / f"{session_id}.json"
            atomic_json(schedule_path, schedule, create=True)
    except (ManifestError, ValueError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(f"schedule={schedule_path}")
    print(f"cells={len(schedule['cells'])}")
    if args.dry_run:
        for cell in schedule["cells"]:
            print(
                "dry-run "
                f"repetition={cell['repetition']} size={cell['size']} "
                f"profile={cell['profile']} query_index={cell['query_index']}"
            )
        return 0

    env = os.environ.copy()
    env["PIR_FORMAL_RUN"] = "1"
    if args.allow_low_memory:
        env["PIR_ALLOW_LOW_MEMORY"] = "1"
    if args.allow_unstable_cpu:
        env["PIR_ALLOW_UNSTABLE_CPU"] = "1"

    first_pending = next((cell for cell in schedule["cells"] if cell["status"] != "passed"), None)
    if first_pending is None:
        print("status=already-complete")
        return 0
    build_command = [
        str(RUNNER),
        f"--size={first_pending['size']}",
        "--preproc-profile=dense",
        "--build-only",
    ]
    build_result = subprocess.run(build_command, cwd=PROJECT_ROOT, env=env, check=False)
    if build_result.returncode != 0:
        print("error: matrix pre-build failed", file=sys.stderr)
        return build_result.returncode

    for cell in schedule["cells"]:
        if cell["status"] == "passed":
            continue
        command = [
            str(RUNNER),
            f"--size={cell['size']}",
            f"--preproc-profile={cell['profile']}",
            f"--query-index={cell['query_index']}",
            f"--run-id={cell['run_id']}",
            "--skip-build",
        ]
        if args.cpu_set:
            command.append(f"--cpu-set={args.cpu_set}")
        cell["started_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        cell["status"] = "running"
        atomic_json(schedule_path, schedule)
        result = subprocess.run(command, cwd=PROJECT_ROOT, env=env, check=False)
        cell["finished_at"] = dt.datetime.now(dt.timezone.utc).isoformat()
        cell["exit_code"] = result.returncode
        cell["status"] = "passed" if result.returncode == 0 else "failed"
        atomic_json(schedule_path, schedule)
        if result.returncode != 0:
            print(f"error: matrix stopped at {cell['run_id']}", file=sys.stderr)
            return result.returncode
    print("status=complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
