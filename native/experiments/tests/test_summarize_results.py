from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from native.experiments.paper_config import DEFAULT_MANIFEST, sha256_file
from native.experiments.summarize_results import (
    ParseError,
    parse_run,
    summarize,
    validate_schedule,
)


RUN_LOG = """database_profile=1gib
database_rows=32768
database_columns=32768
query_index=32764
preproc_profile=negacyclic-both
client_main_pad_backend_lifecycle=ephemeral-per-operation
client_main_pad_backend_cached_bytes=0
[STAGE0_TIMING] scope=server stage=main_hint_matrix_product duration_ms=22000 duration_s=22
[STAGE0_TIMING] scope=global stage=offline_H2_matrix_product duration_ms=24000 duration_s=24
[STAGE0_TIMING] scope=preprocessing stage=total duration_ms=140000 duration_s=140
[STAGE0_TIMING] scope=prepare stage=total duration_ms=400 duration_s=0.4
[STAGE0_TIMING] scope=online_server stage=database_Du duration_ms=190 duration_s=0.19
[STAGE0_TIMING] scope=online stage=total_without_prepare duration_ms=198 duration_s=0.198
Global Prepr (s) : 57
Client Local Prepr (s) : 69
Server Per-Client Prepr (s) : 14
Hints (MiB) : 1280
Long Term State (KiB) : 256
Main Pad Backend State (KiB) : 0
Main Pad Public Seed (bytes) : 32
Online State (KiB) : 3763
Offline Up (KiB) : 10240
Offline Down (KiB) : 10240
Prep Up (Kib) : 952
Prep Down (KiB) : 1792
Query Up (KiB) : 157
Query Down (KiB) : 158
Server Prepa Comp (s) : 0.32
Client Prepa Pre Req (s) : 0.03
Client Prepa Post Req (s) : 0.01
Query: Server Comp (s) : 0.19
Query: Client Req Gen (ms) : 2.5
Query: Client Decryption (ms) : 0.02
Query: Client Verification (ms) : 2.7
End-to-end test done.
[  PASSED  ] 1 test.
"""


class SummarizeResultsTest(unittest.TestCase):
    def make_run(self, root: Path, valid: bool = True) -> Path:
        run = root / "run"
        run.mkdir()
        manifest_sha = sha256_file(DEFAULT_MANIFEST)
        (run / "metadata.txt").write_text(
            "\n".join(
                (
                    "run_id=test-run",
                    "database_profile=1gib",
                    "database_rows=32768",
                    "database_columns=32768",
                    "preproc_profile=negacyclic-both",
                    "query_index=32764",
                    "client_main_pad_backend_lifecycle=ephemeral-per-operation",
                    "client_main_pad_backend_cached_bytes=0",
                    f"manifest_sha256={manifest_sha}",
                    "run_exit_code=0",
                )
            )
            + "\n",
            encoding="utf-8",
        )
        (run / "run.log").write_text(RUN_LOG if valid else "truncated\n", encoding="utf-8")
        (run / "run.time.txt").write_text(
            "Maximum resident set size (kbytes): 12000000\n"
            "User time (seconds): 139\nSystem time (seconds): 4\n",
            encoding="utf-8",
        )
        return run

    def test_parse_complete_run(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            row = parse_run(
                self.make_run(Path(directory)), sha256_file(DEFAULT_MANIFEST)
            )
            self.assertEqual(row["total_preprocessing_seconds"], 140)
            self.assertEqual(row["clp_seconds"], 83)
            self.assertAlmostEqual(row["online_client_milliseconds"], 5.22)
            self.assertEqual(row["peak_rss_kib"], 12000000)
            self.assertEqual(row["main_pad_backend_state_kib"], 0)
            self.assertEqual(row["main_pad_public_seed_bytes"], 32)

    def test_incomplete_run_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ParseError):
                parse_run(
                    self.make_run(Path(directory), valid=False),
                    sha256_file(DEFAULT_MANIFEST),
                )

    def test_cached_client_main_pad_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(Path(directory))
            metadata = run / "metadata.txt"
            metadata.write_text(
                metadata.read_text(encoding="utf-8").replace(
                    "client_main_pad_backend_cached_bytes=0",
                    "client_main_pad_backend_cached_bytes=4096",
                ),
                encoding="utf-8",
            )
            with self.assertRaises(ParseError):
                parse_run(run, sha256_file(DEFAULT_MANIFEST))

    def test_legacy_run_without_lifecycle_metrics_still_parses(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            run = self.make_run(Path(directory))
            for filename in ("metadata.txt", "run.log"):
                path = run / filename
                text = path.read_text(encoding="utf-8")
                text = text.replace(
                    "client_main_pad_backend_lifecycle=ephemeral-per-operation\n", ""
                )
                text = text.replace("client_main_pad_backend_cached_bytes=0\n", "")
                text = text.replace("Main Pad Backend State (KiB) : 0\n", "")
                text = text.replace("Main Pad Public Seed (bytes) : 32\n", "")
                path.write_text(text, encoding="utf-8")

            row = parse_run(run, sha256_file(DEFAULT_MANIFEST))
            self.assertNotIn("main_pad_backend_state_kib", row)
            self.assertNotIn("main_pad_public_seed_bytes", row)

    def test_confidence_interval_requires_three_runs(self) -> None:
        self.assertIsNone(summarize([1.0, 2.0])["ci95_low"])
        self.assertIsNotNone(summarize([1.0, 2.0, 3.0])["ci95_low"])

    def test_schedule_must_be_complete_and_hash_matched(self) -> None:
        digest = sha256_file(DEFAULT_MANIFEST)
        schedule = {
            "schema_version": 1,
            "manifest_id": "paper-v1",
            "manifest_sha256": digest,
            "cells": [
                {
                    "run_id": "test-run",
                    "size": "1gib",
                    "profile": "dense",
                    "query_index": 32764,
                    "repetition": 1,
                    "order_index": 1,
                    "status": "passed",
                }
            ],
        }
        self.assertIn(
            "test-run", validate_schedule(schedule, "paper-v1", digest)
        )
        schedule["cells"][0]["status"] = "failed"
        with self.assertRaises(ParseError):
            validate_schedule(schedule, "paper-v1", digest)
        schedule["cells"][0]["status"] = "passed"
        with self.assertRaises(ParseError):
            validate_schedule(schedule, "paper-v1", "0" * 64)


if __name__ == "__main__":
    unittest.main()
