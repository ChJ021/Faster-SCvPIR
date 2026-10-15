#!/usr/bin/env python3
"""Audit a DECLARED classical lattice-attack model, not all cryptanalysis.

Run with system Python; each isolated estimator runs under SageMath 9.5.
Estimator results are evaluated afresh. See README.md in this directory.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import datetime
import hashlib
import json
import math
import os
from pathlib import Path
import subprocess
import sys
import tarfile

PINS = {
    "162c505": "b24fab5925443b51c9b2c734576441c7c8d5ddd77be35aa46717191bd55261f2",
    "4195c66": "c081bfd1cb3be24b78ce5a6dd8bae1350f6bec25916e02e32b2428ddced58f67",
}
LAYOUTS = ("256mib", "512mib", "1gib", "2gib", "4gib")


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_snapshot(cache, commit):
    """Check archive digest AND every extracted estimator source file."""
    archive = cache / "archives" / f"lattice-estimator-{commit}.tar.gz"
    source = cache / "sources" / f"lattice-estimator-{commit}"
    if digest(archive) != PINS[commit]:
        raise ValueError(f"archive hash mismatch: {commit}")
    with tarfile.open(archive) as tar:
        checked = 0
        for member in tar.getmembers():
            relative = Path(*Path(member.name).parts[1:])
            if member.isfile() and relative.parts[:1] == ("estimator",):
                if (source / relative).read_bytes() != tar.extractfile(member).read():
                    raise ValueError(f"modified estimator source: {relative}")
                checked += 1
    if not checked:
        raise ValueError("no estimator files verified")
    return source


def instances(config):
    p, c, db = config["parameters"], config["current"], config["database"]
    if p["main_error_variance"] != 8 or p["fhe"]["error_variance"] != 8:
        raise ValueError("this profile requires binomial variance 8 (eta=16)")
    if config["targets"]["deployment_targets"] != 1:
        raise ValueError("this profile is single-target only")
    ternary = {"kind": "uniform", "a": -1, "b": 1}
    binomial = {"kind": "centered_binomial", "eta": 16}
    gaussian = {"kind": "discrete_gaussian", "stddev": p["offline_error_stddev"]}
    for stage in ("main", "offline"):
        m = db["columns" if stage == "main" else "rows"]
        for kind in ("dense", "structured"):
            n = c[f"{stage}_{'lwe_dimension' if kind == 'dense' else 'ring_degree'}"]
            q = p[f"q_{stage}"]
            if kind == "structured" and (m % n or (q - 1) % (2 * n)):
                raise ValueError("incompatible ring/layout/NTT modulus")
            name = f"{kind}-{stage}"
            yield name, "162c505" if kind == "dense" else "4195c66", {
                "problem": "lwe", "n": n, "q": q, "m": m,
                "secret": ternary, "error": binomial if stage == "main" else gaussian,
                "method": "full", "attack_profile": "paper-lattice", "tag": name,
            }
            if stage == "main":
                bound = db["rows"] * (2 * p["plaintext_modulus"] - 1)
                if bound >= q:
                    raise ValueError("integer binding bound must be smaller than q")
                yield f"{kind}-binding", "162c505", {
                    "problem": "sis", "n": n, "q": q, "m": m,
                    "norm": "infinity", "length_bound": bound,
                    "method": "full", "attack_profile": "paper-lattice",
                    "tag": f"{kind}-binding",
                }
    fhe = p["fhe"]
    yield "bfv", "162c505", {
        "problem": "lwe", "n": fhe["ring_degree"], "q": math.prod(fhe["moduli"]),
        "m": "infinity", "secret": binomial, "error": binomial,
        "method": "full", "attack_profile": "paper-lattice", "tag": "bfv",
    }


def assessment(response, target=128):
    # Never interpret a missing, infinite or failed estimate as a pass.
    if response.get("status") != "ok" or not response.get("complete_declared_profile"):
        return "INCONCLUSIVE"
    bits = response.get("minimum_rop_bits")
    if not isinstance(bits, (int, float)) or not math.isfinite(bits):
        return "INCONCLUSIVE"
    return "PASS-IN-MODEL" if bits >= target else "FAIL"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--configs", type=Path, default=Path(__file__).parent / "configs")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--project-root", type=Path, help="also compare parameters with native source")
    parser.add_argument("--jobs", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()
    version = subprocess.check_output(["sage", "--version"], text=True).strip()
    if not version.startswith("SageMath version 9.5"):
        raise ValueError(f"expected SageMath 9.5, found {version}")
    sources = {commit: verify_snapshot(args.cache, commit) for commit in PINS}
    # Refuse to silently overwrite an earlier audit.
    args.output.mkdir(parents=True, exist_ok=False)
    worker = Path(__file__).with_name("model_worker.py")
    source_check = {}
    if args.project_root:
        sys.path.insert(0, str(args.project_root.resolve()))
        from native.security.model import config_from_current_source
        for relative in ("native/security/model.py",
                         "native/vendor/Verifiable-Hintless-PIR/hintless_simplepir/new_pir_test.cc",
                         "native/vendor/Verifiable-Hintless-PIR/verisimplepir/src/lib/pir/utils.h"):
            source_check[relative] = digest(args.project_root / relative)
    tasks, layouts, configs = {}, {}, {}
    for layout in LAYOUTS:
        config = json.loads((args.configs / f"{layout}.json").read_text())
        if args.project_root:
            live = config_from_current_source(config, args.project_root)
            if live["parameters"] != config["parameters"] or live["current"] != config["current"]:
                raise ValueError(f"runtime cryptographic parameters mismatch: {layout}")
        configs[layout] = config
        layouts[layout] = {}
        for name, commit, request in instances(config):
            key = hashlib.sha256(json.dumps([commit, request], sort_keys=True).encode()).hexdigest()
            tasks[key] = (commit, request)
            layouts[layout][name] = key

    def run(key):
        commit, request = tasks[key]
        request_path = args.output / f"{key}.request.json"
        request_path.write_text(json.dumps(request, indent=2) + "\n")
        env = dict(os.environ, OMP_NUM_THREADS="1", OPENBLAS_NUM_THREADS="1")
        try:
            completed = subprocess.run(
                ["sage", "-python", str(worker), "--estimator", str(sources[commit]),
                 "--input", str(request_path)], capture_output=True, text=True,
                timeout=args.timeout, env=env)
            response = json.loads(completed.stdout)
            if completed.returncode:
                response["status"] = "error"
            if completed.stderr:
                response["stderr"] = completed.stderr[-4000:]
        except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
            response = {"status": "error", "error": str(exc)}
        response.update(estimator_commit=commit, request=request)
        response["assessment"] = assessment(response)
        (args.output / f"{key}.result.json").write_text(json.dumps(response, indent=2) + "\n")
        print(commit, request["tag"], request["m"], response["assessment"],
              response.get("minimum_rop_bits"), flush=True)
        return key, response

    evidence = {}
    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for future in as_completed([pool.submit(run, key) for key in tasks]):
            key, response = future.result()
            evidence[key] = response
    rows = {layout: {name: evidence[key] for name, key in mapping.items()}
            for layout, mapping in layouts.items()}
    statuses = [r["assessment"] for r in evidence.values()]
    status = ("FAIL" if "FAIL" in statuses else
              "INCONCLUSIVE" if "INCONCLUSIVE" in statuses else "PASS-IN-MODEL")
    report = {
        "status": status, "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "model": "LWE/RLWE: MATZOV/GSA lattice attacks; SIS: ADPS16 Core-SVP/LGSA",
        "excluded": ["BKW", "Arora-GB", "ring-specific attacks", "quantum attacks",
                     "public-seed/feedback/KDM security reductions", "multi-target loss"],
        "target_bits": 128, "sage_version": version, "pins": PINS,
        "worker_sha256": digest(worker), "driver_sha256": digest(Path(__file__)),
        "runtime_source_sha256": source_check, "configurations": configs,
        "distinct_requests": len(tasks), "layouts": rows,
    }
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(status, "report:", args.output / "report.json")
    return 0 if status == "PASS-IN-MODEL" else 1


if __name__ == "__main__":
    raise SystemExit(main())
