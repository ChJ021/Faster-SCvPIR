#!/usr/bin/env python3
"""Parse paper-v1 logs into reviewer-facing CSV tables."""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import math
import re
import statistics
import sys
from pathlib import Path
from typing import Any, Iterable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from native.experiments.paper_config import (  # type: ignore
        DEFAULT_CHECKSUM,
        DEFAULT_MANIFEST,
        ManifestError,
        load_manifest,
        sha256_file,
    )
else:
    from .paper_config import (
        DEFAULT_CHECKSUM,
        DEFAULT_MANIFEST,
        ManifestError,
        load_manifest,
        sha256_file,
    )


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_LOG_ROOT = PROJECT_ROOT / "native/logs/paper-v1"
DEFAULT_BASELINE = PROJECT_ROOT / "native/baselines/small-client-vpir-paper.json"
DEFAULT_OUTPUT_ROOT = PROJECT_ROOT / "native/results/paper-v1"
STAGE_RE = re.compile(
    r"\[STAGE0_TIMING\]\s+scope=(\S+)\s+stage=(\S+)\s+"
    r"duration_ms=([0-9.eE+-]+)\s+duration_s=([0-9.eE+-]+)"
)
METRIC_RE = re.compile(r"^([^:\n][^\n]*?)\s+:\s+([0-9.eE+-]+)\s*$")
T_CRITICAL_95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
    10: 2.228,
    11: 2.201,
    12: 2.179,
    13: 2.160,
    14: 2.145,
    15: 2.131,
    16: 2.120,
    17: 2.110,
    18: 2.101,
    19: 2.093,
    20: 2.086,
    21: 2.080,
    22: 2.074,
    23: 2.069,
    24: 2.064,
    25: 2.060,
    26: 2.056,
    27: 2.052,
    28: 2.048,
    29: 2.045,
    30: 2.042,
}


class ParseError(ValueError):
    """Raised when a run is incomplete or internally inconsistent."""


def validate_schedule(
    schedule: dict[str, Any], manifest_id: str, manifest_sha256: str
) -> dict[str, dict[str, Any]]:
    if schedule.get("schema_version") != 1:
        raise ParseError("schedule schema_version must be 1")
    if (
        schedule.get("manifest_id") != manifest_id
        or schedule.get("manifest_sha256") != manifest_sha256
    ):
        raise ParseError("schedule does not use the current frozen manifest")
    cells = schedule.get("cells")
    if not isinstance(cells, list) or not cells:
        raise ParseError("schedule has no experiment cells")
    by_run_id: dict[str, dict[str, Any]] = {}
    incomplete: list[str] = []
    for cell in cells:
        if not isinstance(cell, dict):
            raise ParseError("schedule contains a non-object cell")
        missing = [
            key
            for key in ("run_id", "size", "profile", "query_index", "repetition", "order_index", "status")
            if key not in cell
        ]
        if missing:
            raise ParseError(f"schedule cell is missing {', '.join(missing)}")
        run_id = cell["run_id"]
        if not isinstance(run_id, str) or not run_id:
            raise ParseError("schedule cell has an invalid run_id")
        if run_id in by_run_id:
            raise ParseError(f"schedule repeats run_id {run_id}")
        by_run_id[run_id] = cell
        if cell["status"] != "passed":
            incomplete.append(f"{run_id}:{cell['status']}")
    if incomplete:
        preview = ", ".join(incomplete[:4])
        suffix = " ..." if len(incomplete) > 4 else ""
        raise ParseError(
            f"schedule is incomplete ({len(incomplete)} cells): {preview}{suffix}"
        )
    return by_run_id


def key_values(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def parse_time(path: Path) -> dict[str, float]:
    result: dict[str, float] = {}
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if stripped.startswith("Maximum resident set size (kbytes):"):
            result["peak_rss_kib"] = float(stripped.rsplit(":", 1)[1].strip())
        elif stripped.startswith("User time (seconds):"):
            result["process_user_seconds"] = float(stripped.rsplit(":", 1)[1].strip())
        elif stripped.startswith("System time (seconds):"):
            result["process_system_seconds"] = float(stripped.rsplit(":", 1)[1].strip())
    return result


def parse_run(run_dir: Path, expected_manifest_sha: str) -> dict[str, Any]:
    metadata_path = run_dir / "metadata.txt"
    log_path = run_dir / "run.log"
    time_path = run_dir / "run.time.txt"
    missing = [path.name for path in (metadata_path, log_path, time_path) if not path.is_file()]
    if missing:
        raise ParseError(f"{run_dir}: missing {', '.join(missing)}")
    metadata = key_values(metadata_path)
    required_metadata = (
        "run_id",
        "database_profile",
        "database_rows",
        "database_columns",
        "preproc_profile",
        "query_index",
        "manifest_sha256",
        "run_exit_code",
    )
    missing_keys = [key for key in required_metadata if key not in metadata]
    if missing_keys:
        raise ParseError(f"{run_dir}: metadata missing {', '.join(missing_keys)}")
    if metadata["manifest_sha256"] != expected_manifest_sha:
        raise ParseError(f"{run_dir}: manifest hash differs from paper-v1")
    if metadata["run_exit_code"] != "0":
        raise ParseError(f"{run_dir}: run_exit_code={metadata['run_exit_code']}")

    text = log_path.read_text(encoding="utf-8", errors="replace")
    if "[  PASSED  ] 1 test." not in text or "End-to-end test done." not in text:
        raise ParseError(f"{run_dir}: correctness marker is missing")
    expected_markers = {
        "database_profile": metadata["database_profile"],
        "database_rows": metadata["database_rows"],
        "database_columns": metadata["database_columns"],
        "query_index": metadata["query_index"],
        "preproc_profile": metadata["preproc_profile"],
    }
    for key, value in expected_markers.items():
        if f"{key}={value}" not in text:
            raise ParseError(f"{run_dir}: log/metadata mismatch for {key}")
    lifecycle = metadata.get("client_main_pad_backend_lifecycle")
    if lifecycle is not None:
        if lifecycle != "ephemeral-per-operation":
            raise ParseError(f"{run_dir}: unsupported client main-pad lifecycle")
        if metadata.get("client_main_pad_backend_cached_bytes") != "0":
            raise ParseError(f"{run_dir}: client main-pad backend is cached")
        if f"client_main_pad_backend_lifecycle={lifecycle}" not in text:
            raise ParseError(f"{run_dir}: client main-pad lifecycle marker differs")
        if "client_main_pad_backend_cached_bytes=0" not in text:
            raise ParseError(f"{run_dir}: client main-pad cache marker differs")

    stages: dict[str, float] = {}
    for match in STAGE_RE.finditer(text):
        stages[f"stage.{match.group(1)}.{match.group(2)}.seconds"] = float(match.group(4))
    required_stages = (
        "stage.server.main_hint_matrix_product.seconds",
        "stage.global.offline_H2_matrix_product.seconds",
        "stage.preprocessing.total.seconds",
        "stage.prepare.total.seconds",
        "stage.online_server.database_Du.seconds",
        "stage.online.total_without_prepare.seconds",
    )
    missing_stages = [key for key in required_stages if key not in stages]
    if missing_stages:
        raise ParseError(f"{run_dir}: missing timing stages {', '.join(missing_stages)}")

    reported: dict[str, float] = {}
    for line in text.splitlines():
        match = METRIC_RE.match(line.strip())
        if match:
            reported[match.group(1)] = float(match.group(2))
    required_reported = (
        "Global Prepr (s)",
        "Client Local Prepr (s)",
        "Server Per-Client Prepr (s)",
        "Hints (MiB)",
        "Long Term State (KiB)",
        "Online State (KiB)",
        "Offline Up (KiB)",
        "Offline Down (KiB)",
        "Prep Up (Kib)",
        "Prep Down (KiB)",
        "Query Up (KiB)",
        "Query Down (KiB)",
        "Server Prepa Comp (s)",
        "Client Prepa Pre Req (s)",
        "Client Prepa Post Req (s)",
        "Query: Server Comp (s)",
        "Query: Client Req Gen (ms)",
        "Query: Client Decryption (ms)",
        "Query: Client Verification (ms)",
    )
    missing_reported = [key for key in required_reported if key not in reported]
    if missing_reported:
        raise ParseError(f"{run_dir}: missing reported metrics {', '.join(missing_reported)}")
    if lifecycle is not None:
        if reported.get("Main Pad Backend State (KiB)") != 0:
            raise ParseError(
                f"{run_dir}: ephemeral client reports nonzero main-pad state"
            )
        if "Main Pad Public Seed (bytes)" not in reported:
            raise ParseError(f"{run_dir}: main-pad public seed size is missing")

    row: dict[str, Any] = {
        "run_id": metadata["run_id"],
        "size": metadata["database_profile"],
        "profile": metadata["preproc_profile"],
        "rows": int(metadata["database_rows"]),
        "columns": int(metadata["database_columns"]),
        "query_index": int(metadata["query_index"]),
        "manifest_sha256": metadata["manifest_sha256"],
        "total_preprocessing_seconds": stages["stage.preprocessing.total.seconds"],
        "main_hint_seconds": stages["stage.server.main_hint_matrix_product.seconds"],
        "offline_h2_seconds": stages["stage.global.offline_H2_matrix_product.seconds"],
        "dlp_seconds": reported["Global Prepr (s)"],
        "clp_seconds": reported["Client Local Prepr (s)"] + reported["Server Per-Client Prepr (s)"],
        "client_local_preprocessing_seconds": reported["Client Local Prepr (s)"],
        "server_per_client_preprocessing_seconds": reported["Server Per-Client Prepr (s)"],
        "query_preparation_seconds": stages["stage.prepare.total.seconds"],
        "query_preparation_server_seconds": reported["Server Prepa Comp (s)"],
        "query_preparation_client_seconds": reported["Client Prepa Pre Req (s)"] + reported["Client Prepa Post Req (s)"],
        "online_total_seconds": stages["stage.online.total_without_prepare.seconds"],
        "online_server_seconds": reported["Query: Server Comp (s)"],
        "online_client_milliseconds": reported["Query: Client Req Gen (ms)"] + reported["Query: Client Decryption (ms)"] + reported["Query: Client Verification (ms)"],
        "hint_mib": reported["Hints (MiB)"],
        "long_term_state_kib": reported["Long Term State (KiB)"],
        "online_state_kib": reported["Online State (KiB)"],
        "offline_upload_kib": reported["Offline Up (KiB)"],
        "offline_download_kib": reported["Offline Down (KiB)"],
        "query_preparation_upload_kib": reported["Prep Up (Kib)"],
        "query_preparation_download_kib": reported["Prep Down (KiB)"],
        "query_upload_kib": reported["Query Up (KiB)"],
        "query_download_kib": reported["Query Down (KiB)"],
        "correct": 1,
        "run_directory": str(run_dir),
    }
    if "Main Pad Backend State (KiB)" in reported:
        row["main_pad_backend_state_kib"] = reported[
            "Main Pad Backend State (KiB)"
        ]
    if "Main Pad Public Seed (bytes)" in reported:
        row["main_pad_public_seed_bytes"] = reported[
            "Main Pad Public Seed (bytes)"
        ]
    row.update(parse_time(time_path))
    return row


def metric_columns(rows: list[dict[str, Any]]) -> list[str]:
    excluded = {
        "run_id",
        "size",
        "profile",
        "rows",
        "columns",
        "query_index",
        "repetition",
        "order_index",
        "manifest_sha256",
        "correct",
        "run_directory",
    }
    return sorted(
        key
        for key in set().union(*(row.keys() for row in rows))
        if key not in excluded and all(isinstance(row.get(key), (int, float)) for row in rows)
    )


def summarize(values: list[float]) -> dict[str, float | int | None]:
    count = len(values)
    mean = statistics.fmean(values)
    sample_sd = statistics.stdev(values) if count >= 2 else None
    half_width = None
    if count >= 3 and sample_sd is not None:
        critical = T_CRITICAL_95.get(count - 1, 1.96)
        half_width = critical * sample_sd / math.sqrt(count)
    return {
        "n": count,
        "mean": mean,
        "sample_sd": sample_sd,
        "median": statistics.median(values),
        "minimum": min(values),
        "maximum": max(values),
        "ci95_low": mean - half_width if half_width is not None else None,
        "ci95_high": mean + half_width if half_width is not None else None,
    }


def write_csv(path: Path, rows: Iterable[dict[str, Any]], fieldnames: list[str]) -> None:
    with path.open("x", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log-root", type=Path, default=DEFAULT_LOG_ROOT)
    parser.add_argument("--session-id")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--paper-baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument(
        "--allow-unscheduled",
        action="store_true",
        help="allow manual diagnostic runs without a completed matrix schedule",
    )
    args = parser.parse_args()
    try:
        manifest = load_manifest(DEFAULT_MANIFEST, DEFAULT_CHECKSUM)
        manifest_sha = sha256_file(DEFAULT_MANIFEST)
        paper = json.loads(args.paper_baseline.read_text(encoding="utf-8"))
        all_candidates = sorted(args.log_root.glob("*/*/*/metadata.txt"))
        candidates = all_candidates
        schedule_path: Path | None = None
        schedule: dict[str, Any] | None = None
        schedule_cells: dict[str, dict[str, Any]] = {}
        if args.session_id:
            possible_schedule = args.log_root / "schedules" / f"{args.session_id}.json"
            if possible_schedule.is_file():
                schedule_path = possible_schedule
                schedule = json.loads(schedule_path.read_text(encoding="utf-8"))
                schedule_cells = validate_schedule(
                    schedule, manifest["manifest_id"], manifest_sha
                )
                paths_by_run: dict[str, list[Path]] = {}
                for path in all_candidates:
                    paths_by_run.setdefault(path.parent.name, []).append(path)
                missing_runs = [
                    run_id for run_id in schedule_cells if run_id not in paths_by_run
                ]
                duplicate_runs = [
                    run_id
                    for run_id in schedule_cells
                    if len(paths_by_run.get(run_id, [])) > 1
                ]
                if missing_runs:
                    raise ParseError(
                        "completed schedule is missing logs for "
                        + ", ".join(missing_runs[:4])
                    )
                if duplicate_runs:
                    raise ParseError(
                        "multiple log directories use scheduled run IDs: "
                        + ", ".join(duplicate_runs[:4])
                    )
                candidates = [
                    paths_by_run[cell["run_id"]][0] for cell in schedule["cells"]
                ]
            elif args.allow_unscheduled:
                candidates = [
                    path
                    for path in candidates
                    if path.parent.name.startswith(args.session_id)
                ]
            else:
                raise ParseError(
                    f"completed schedule not found for session {args.session_id}; "
                    "use --allow-unscheduled only for diagnostics"
                )
        if not candidates:
            raise ParseError("no matching paper-v1 runs were found")
        runs = [parse_run(path.parent, manifest_sha) for path in candidates]
        if schedule is not None:
            for row in runs:
                cell = schedule_cells[row["run_id"]]
                expected = {
                    "size": cell["size"],
                    "profile": cell["profile"],
                    "query_index": int(cell["query_index"]),
                }
                for key, value in expected.items():
                    if row[key] != value:
                        raise ParseError(
                            f"{row['run_id']}: log disagrees with schedule for {key}"
                        )
                row["repetition"] = int(cell["repetition"])
                row["order_index"] = int(cell["order_index"])
        metrics = metric_columns(runs)
        summary_rows: list[dict[str, Any]] = []
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for row in runs:
            grouped.setdefault((row["size"], row["profile"]), []).append(row)
        for (size, profile), group in sorted(grouped.items()):
            for metric in metrics:
                values = [float(row[metric]) for row in group if metric in row]
                stats = summarize(values)
                summary_rows.append({"size": size, "profile": profile, "metric": metric, **stats})

        mean_index = {
            (row["size"], row["profile"], row["metric"]): row["mean"]
            for row in summary_rows
        }
        run_index = {
            (row["size"], row["profile"], row["repetition"]): row
            for row in runs
            if "repetition" in row
        }
        speedup_rows: list[dict[str, Any]] = []
        for row in summary_rows:
            baseline = mean_index.get((row["size"], "dense", row["metric"]))
            if baseline is None or row["mean"] in (None, 0):
                continue
            paired_values: list[float] = []
            for run in runs:
                if (
                    run["size"] != row["size"]
                    or run["profile"] != row["profile"]
                    or "repetition" not in run
                ):
                    continue
                dense_run = run_index.get(
                    (run["size"], "dense", run["repetition"])
                )
                if (
                    dense_run is not None
                    and row["metric"] in dense_run
                    and row["metric"] in run
                    and float(run[row["metric"]]) != 0
                ):
                    paired_values.append(
                        float(dense_run[row["metric"]])
                        / float(run[row["metric"]])
                    )
            paired = summarize(paired_values) if paired_values else None
            speedup_rows.append(
                {
                    "size": row["size"],
                    "profile": row["profile"],
                    "metric": row["metric"],
                    "dense_mean": baseline,
                    "profile_mean": row["mean"],
                    "same_host_speedup": baseline / row["mean"],
                    "paired_n": paired["n"] if paired else None,
                    "paired_speedup_mean": paired["mean"] if paired else None,
                    "paired_speedup_sample_sd": paired["sample_sd"] if paired else None,
                    "paired_speedup_ci95_low": paired["ci95_low"] if paired else None,
                    "paired_speedup_ci95_high": paired["ci95_high"] if paired else None,
                }
            )

        comparison_map = {
            "one_time_dlp_seconds": "dlp_seconds",
            "one_time_clp_seconds": "clp_seconds",
            "query_preparation_server_seconds": "query_preparation_server_seconds",
            "query_preparation_client_seconds": "query_preparation_client_seconds",
            "online_server_seconds": "online_server_seconds",
            "online_client_milliseconds": "online_client_milliseconds",
        }
        comparison_rows: list[dict[str, Any]] = []
        for size in ("256mib", "512mib", "1gib", "2gib", "4gib"):
            published = paper["results"].get(size, {})
            published_values: dict[str, Any] = {
                "one_time_dlp_seconds": published.get("one_time_dlp_seconds"),
                "one_time_clp_seconds": published.get("one_time_clp_seconds"),
            }
            if published.get("query_preparation"):
                published_values.update(
                    {
                        "query_preparation_server_seconds": published["query_preparation"]["server_seconds"],
                        "query_preparation_client_seconds": published["query_preparation"]["client_seconds"],
                        "online_server_seconds": published["online"]["server_milliseconds"] / 1000,
                        "online_client_milliseconds": published["online"]["client_milliseconds"],
                    }
                )
            for paper_metric, local_metric in comparison_map.items():
                value = published_values.get(paper_metric)
                if isinstance(value, dict):
                    value = value.get("value")
                dense = mean_index.get((size, "dense", local_metric))
                structured = mean_index.get((size, "negacyclic-both", local_metric))
                comparison_rows.append(
                    {
                        "size": size,
                        "metric": paper_metric,
                        "published_value": value,
                        "local_dense_mean": dense,
                        "local_negacyclic_both_mean": structured,
                        "same_host_speedup": dense / structured if dense and structured else None,
                        "cross_hardware_reference_ratio": value / structured if isinstance(value, (int, float)) and structured else None,
                        "comparability": "secondary-cross-hardware-reference-only" if value is not None else "not-reported-by-source",
                    }
                )

        output_name = args.session_id or dt.datetime.now(dt.timezone.utc).strftime(
            "aggregate-%Y%m%dT%H%M%SZ"
        )
        output = (args.output or DEFAULT_OUTPUT_ROOT / output_name).resolve()
        output.mkdir(parents=True, exist_ok=False)
        run_fields = [
            "run_id", "size", "profile", "rows", "columns", "query_index",
            "repetition", "order_index", "manifest_sha256", "correct", *metrics,
            "run_directory",
        ]
        write_csv(output / "runs.csv", runs, run_fields)
        write_csv(
            output / "summary.csv",
            summary_rows,
            ["size", "profile", "metric", "n", "mean", "sample_sd", "median", "minimum", "maximum", "ci95_low", "ci95_high"],
        )
        write_csv(
            output / "speedups.csv",
            speedup_rows,
            [
                "size", "profile", "metric", "dense_mean", "profile_mean",
                "same_host_speedup", "paired_n", "paired_speedup_mean",
                "paired_speedup_sample_sd", "paired_speedup_ci95_low",
                "paired_speedup_ci95_high",
            ],
        )
        write_csv(
            output / "comparison-small-client.csv",
            comparison_rows,
            ["size", "metric", "published_value", "local_dense_mean", "local_negacyclic_both_mean", "same_host_speedup", "cross_hardware_reference_ratio", "comparability"],
        )
        provenance = {
            "schema_version": 1,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "manifest_id": manifest["manifest_id"],
            "manifest_sha256": manifest_sha,
            "paper_baseline_sha256": sha256_file(args.paper_baseline),
            "session_id": args.session_id,
            "schedule": str(schedule_path) if schedule_path else None,
            "schedule_sha256": sha256_file(schedule_path) if schedule_path else None,
            "unscheduled_diagnostic": schedule_path is None,
            "run_count": len(runs),
            "source_files": [
                {
                    "path": str(path),
                    "metadata_sha256": sha256_file(path),
                    "run_log_sha256": sha256_file(path.parent / "run.log"),
                    "time_log_sha256": sha256_file(path.parent / "run.time.txt"),
                }
                for path in candidates
            ],
            "claim_boundary": "same-host speedups are primary; published values are cross-hardware references",
        }
        (output / "manifest.json").write_text(
            json.dumps(provenance, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
    except (ManifestError, ParseError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(f"output={output}")
    print(f"runs={len(runs)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
