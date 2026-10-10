"""Version-pinned, fail-closed interface to the Sage Lattice Estimator."""

from __future__ import annotations

import hashlib
import json
import math
import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Iterable

from .model import (
    MODERN_COMMIT,
    SMALL_CLIENT_COMMIT,
    YPIR_COMMIT,
    SecurityInstance,
)


PAPER_COMMITS = {
    "small-client": SMALL_CLIENT_COMMIT,
    "ypir": YPIR_COMMIT,
}

LOCKED_ESTIMATORS = {
    "small-client": {
        "commit": SMALL_CLIENT_COMMIT,
        "archive_sha256": "b24fab5925443b51c9b2c734576441c7c8d5ddd77be35aa46717191bd55261f2",
    },
    "ypir": {
        "commit": YPIR_COMMIT,
        "archive_sha256": "c081bfd1cb3be24b78ce5a6dd8bae1350f6bec25916e02e32b2428ddced58f67",
    },
    "modern": {
        "commit": MODERN_COMMIT,
        "archive_sha256": "4236adc38031c139c8a2721804d8962d6cacd015fae37f6f5215d2ac7f011060",
    },
}
WORKER_SCHEMA_VERSION = 3


class EstimatorError(RuntimeError):
    """Raised when a pinned estimator cannot produce a complete result."""


class EstimatorRunner:
    def __init__(
        self,
        project_root: Path,
        timeout_seconds: int = 1800,
        parallel_jobs: int = 1,
        bfv_attack_profile: str = "full",
    ) -> None:
        self.project_root = project_root.resolve()
        self.native_root = self.project_root / "native"
        self.source_root = self.native_root / "cache/security/sources"
        self.cache_root = self.native_root / "cache/security/results"
        self.worker = self.native_root / "security/sage_worker.py"
        self.timeout_seconds = timeout_seconds
        self.parallel_jobs = max(1, parallel_jobs)
        self.bfv_attack_profile = bfv_attack_profile
        self.sage_version: str | None = None
        self.cache_root.mkdir(parents=True, exist_ok=True)

    def check_environment(self) -> None:
        missing = []
        for commit in (SMALL_CLIENT_COMMIT, YPIR_COMMIT, MODERN_COMMIT):
            source = self._source_directory(commit)
            marker = source / "estimator/__init__.py"
            digest_marker = source / ".archive-sha256"
            expected_digest = next(
                item["archive_sha256"]
                for item in LOCKED_ESTIMATORS.values()
                if item["commit"] == commit
            )
            if not marker.is_file() or not digest_marker.is_file():
                missing.append(commit)
            elif digest_marker.read_text(encoding="utf-8").strip() != expected_digest:
                raise EstimatorError(f"estimator snapshot marker mismatch for commit {commit}")
        if missing:
            raise EstimatorError(
                "missing pinned estimator snapshots: "
                + ", ".join(missing)
                + "; run native/scripts/setup-security-estimator.sh"
            )
        try:
            completed = subprocess.run(
                ["sage", "--version"],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise EstimatorError(f"cannot execute SageMath: {exc}") from exc
        version = (completed.stdout + completed.stderr).strip()
        if completed.returncode or not version.startswith("SageMath version 9.5"):
            raise EstimatorError(f"expected SageMath 9.5, found: {version or 'unavailable'}")
        self.sage_version = version

    def provenance(self) -> dict[str, Any]:
        lock_file = self.native_root / "security/estimator.lock.sh"
        lock_sha256 = hashlib.sha256(lock_file.read_bytes()).hexdigest()
        return {
            "worker_schema_version": WORKER_SCHEMA_VERSION,
            "sage_version": self.sage_version,
            "lock_file": str(lock_file.relative_to(self.project_root)),
            "lock_file_sha256": lock_sha256,
            "estimators": LOCKED_ESTIMATORS,
        }

    def _source_directory(self, commit: str) -> Path:
        return self.source_root / f"lattice-estimator-{commit}"

    @staticmethod
    def _cache_key(commit: str, spec: dict[str, Any]) -> str:
        canonical = json.dumps(
            {
                "worker_schema_version": WORKER_SCHEMA_VERSION,
                "estimator_commit": commit,
                "request": spec,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _cache_path(self, commit: str, spec: dict[str, Any]) -> Path:
        return self.cache_root / commit / f"{self._cache_key(commit, spec)}.json"

    def _run(self, commit: str, spec: dict[str, Any]) -> dict[str, Any]:
        cache_path = self._cache_path(commit, spec)
        if cache_path.is_file():
            try:
                cached = json.loads(cache_path.read_text(encoding="utf-8"))
                if (
                    cached.get("status") == "ok"
                    and cached.get("worker_schema_version") == WORKER_SCHEMA_VERSION
                ):
                    cached["cache_hit"] = True
                    return cached
            except (OSError, json.JSONDecodeError):
                pass

        cache_path.parent.mkdir(parents=True, exist_ok=True)
        request_file: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w",
                encoding="utf-8",
                prefix="request-",
                suffix=".json",
                dir=cache_path.parent,
                delete=False,
            ) as handle:
                json.dump(spec, handle, sort_keys=True)
                request_file = Path(handle.name)

            environment = os.environ.copy()
            environment.update({"OMP_NUM_THREADS": "1", "OPENBLAS_NUM_THREADS": "1"})
            completed = subprocess.run(
                [
                    "sage",
                    "-python",
                    str(self.worker),
                    "--estimator",
                    str(self._source_directory(commit)),
                    "--input",
                    str(request_file),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                env=environment,
            )
            try:
                response = json.loads(completed.stdout)
            except json.JSONDecodeError:
                response = {
                    "status": "error",
                    "error": f"worker returned exit code {completed.returncode} without valid JSON",
                    "diagnostic_tail": (completed.stdout + "\n" + completed.stderr)[-4000:],
                }
            if completed.stderr.strip():
                response.setdefault("launcher_stderr_tail", completed.stderr[-4000:])
            response.update(
                {
                    "estimator_commit": commit,
                    "worker_schema_version": WORKER_SCHEMA_VERSION,
                    "cache_hit": False,
                    "request": spec,
                }
            )
            if completed.returncode != 0 and response.get("status") == "ok":
                response["status"] = "error"
                response["error"] = f"worker exited with code {completed.returncode}"
            if response.get("status") == "ok":
                temporary = cache_path.with_suffix(".tmp")
                temporary.write_text(
                    json.dumps(response, indent=2, sort_keys=True) + "\n", encoding="utf-8"
                )
                temporary.replace(cache_path)
            return response
        except subprocess.TimeoutExpired as exc:
            return {
                "status": "error",
                "error": f"estimator timed out after {self.timeout_seconds} seconds",
                "diagnostic_tail": ((exc.stdout or "") + "\n" + (exc.stderr or ""))[-4000:],
                "estimator_commit": commit,
                "cache_hit": False,
                "request": spec,
            }
        except OSError as exc:
            return {
                "status": "error",
                "error": f"cannot launch estimator: {exc}",
                "estimator_commit": commit,
                "cache_hit": False,
                "request": spec,
            }
        finally:
            if request_file is not None:
                request_file.unlink(missing_ok=True)

    def estimate(
        self, instance: SecurityInstance, estimator_role: str, method: str
    ) -> dict[str, Any]:
        if estimator_role == "paper":
            commit = PAPER_COMMITS[instance.paper_estimator]
        elif estimator_role == "modern":
            commit = MODERN_COMMIT
        else:
            raise ValueError(f"unknown estimator role: {estimator_role}")
        spec = instance.worker_spec(method)
        if instance.stage == "query-preparation" and method == "full":
            spec["attack_profile"] = self.bfv_attack_profile
        result = self._run(commit, spec)
        result.update(
            {
                "instance": instance.to_dict(),
                "estimator_role": estimator_role,
                "effective_rop_bits": result.get("minimum_rop_bits"),
            }
        )
        return result

    def estimate_both(
        self, instances: Iterable[SecurityInstance], method: str, deployment_targets: int = 1
    ) -> list[dict[str, Any]]:
        penalty = math.log2(deployment_targets)
        tasks = [(instance, role) for instance in instances for role in ("paper", "modern")]

        def run(task: tuple[SecurityInstance, str]) -> dict[str, Any]:
            instance, role = task
            result = self.estimate(instance, role, method)
            bits = result.get("minimum_rop_bits")
            result["multi_target_penalty_bits"] = penalty
            result["effective_rop_bits"] = None if bits is None else bits - penalty
            return result

        with ThreadPoolExecutor(max_workers=min(self.parallel_jobs, len(tasks))) as executor:
            return list(executor.map(run, tasks))
