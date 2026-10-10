#!/usr/bin/env python3
"""Reproduce the two 128-bit YPIR paper calibration points."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from native.security.model import SecurityInstance  # type: ignore
    from native.security.runner import EstimatorRunner  # type: ignore
else:
    from .model import SecurityInstance
    from .runner import EstimatorRunner


TARGET_BITS = 128.0
REFERENCE_BITS = {
    "ypir-paper-d1": 128.5072668654386,
    "ypir-paper-d2": 131.53965108808902,
}
REFERENCE_TOLERANCE_BITS = 0.05


def gaussian(stddev: float) -> dict[str, float | str]:
    return {"kind": "discrete_gaussian", "stddev": stddev}


def calibration_instances() -> list[SecurityInstance]:
    # YPIR Section 4: s_i = sigma_i*sqrt(2*pi), so the estimator
    # standard deviations are 11 and 6.4 respectively.
    return [
        SecurityInstance(
            instance_id="ypir-paper-d1",
            stage="calibration",
            primitive="YPIR RLWE d1",
            estimator_problem="lwe",
            n=1024,
            q=1 << 32,
            m="infinity",
            secret=gaussian(11.0),
            error=gaussian(11.0),
            length_bound=None,
            norm=None,
            paper_estimator="ypir",
            assumption="YPIR USENIX Security 2024 first RLWE instance",
        ),
        SecurityInstance(
            instance_id="ypir-paper-d2",
            stage="calibration",
            primitive="YPIR RLWE d2",
            estimator_problem="lwe",
            n=2048,
            q=(2**28 - 2**16 + 1) * (2**28 - 2**24 - 2**21 + 1),
            m="infinity",
            secret=gaussian(6.4),
            error=gaussian(6.4),
            length_bound=None,
            norm=None,
            paper_estimator="ypir",
            assumption="YPIR USENIX Security 2024 second RLWE instance",
        ),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--timeout", type=int, default=3600)
    args = parser.parse_args()
    project_root = Path(__file__).resolve().parents[2]
    output = (
        args.output
        or project_root
        / "native/results/security"
        / f"calibration-{dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    ).resolve()

    runner = EstimatorRunner(project_root, timeout_seconds=args.timeout, parallel_jobs=2)
    runner.check_environment()
    instances = calibration_instances()
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda item: runner.estimate(item, "paper", "full"), instances))

    passed = True
    for result in results:
        bits = result.get("minimum_rop_bits")
        label = result["instance"]["instance_id"]
        reference = REFERENCE_BITS[label]
        item_passed = (
            result.get("status") == "ok"
            and bits is not None
            and bits >= TARGET_BITS
            and abs(bits - reference) <= REFERENCE_TOLERANCE_BITS
        )
        passed = passed and item_passed
        rendered = "ERR" if bits is None else f"{bits:.2f}"
        print(
            f"CALIBRATION {label} bits={rendered} expected={reference:.2f} "
            f"status={'PASS' if item_passed else 'FAIL'}"
        )

    artifact = {
        "schema_version": 1,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "target_bits": TARGET_BITS,
        "reference_bits": REFERENCE_BITS,
        "reference_tolerance_bits": REFERENCE_TOLERANCE_BITS,
        "method": "full",
        "source": "YPIR, USENIX Security 2024, Section 4 parameter selection",
        "estimator_provenance": runner.provenance(),
        "results": results,
        "status": "pass" if passed else "fail",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"report={output}")
    return 0 if passed else 2


if __name__ == "__main__":
    raise SystemExit(main())
