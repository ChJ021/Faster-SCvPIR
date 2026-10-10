#!/usr/bin/env python3
"""Concise command-line security evaluation for native PIR profiles."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import platform
import shutil
import sys
from pathlib import Path
from typing import Any, Callable

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from native.security.model import (  # type: ignore
        PROFILES,
        ConfigError,
        SecurityInstance,
        candidate_values,
        common_instances,
        config_from_current_source,
        correctness_analysis,
        current_dimension,
        human_binary_size,
        honest_h_sis_bound,
        load_config,
        logical_database_bytes,
        main_instances,
        offline_instances,
        profile_kinds,
    )
    from native.security.runner import EstimatorError, EstimatorRunner  # type: ignore
else:
    from .model import (
        PROFILES,
        ConfigError,
        SecurityInstance,
        candidate_values,
        common_instances,
        config_from_current_source,
        correctness_analysis,
        current_dimension,
        human_binary_size,
        honest_h_sis_bound,
        load_config,
        logical_database_bytes,
        main_instances,
        offline_instances,
        profile_kinds,
    )
    from .runner import EstimatorError, EstimatorRunner


def parse_profiles(raw: str, configured: list[str]) -> list[str]:
    if raw == "all":
        return list(configured)
    profiles = [item.strip() for item in raw.split(",") if item.strip()]
    unknown = sorted(set(profiles) - set(PROFILES))
    if not profiles or unknown:
        raise ConfigError(
            "profiles must be 'all' or a comma-separated subset of " + ", ".join(PROFILES)
        )
    return profiles


def result_passes(result: dict[str, Any], target: float) -> bool:
    bits = result.get("effective_rop_bits")
    return result.get("status") == "ok" and bits is not None and bits >= target


class Audit:
    def __init__(
        self,
        config: dict[str, Any],
        runner: EstimatorRunner,
        method: str,
        verbose: bool,
        include_unbounded_sensitivity: bool,
    ) -> None:
        self.config = config
        self.runner = runner
        self.method = method
        self.verbose = verbose
        self.include_unbounded_sensitivity = include_unbounded_sensitivity
        self.target = float(config["targets"]["computational_bits"])
        self.deployments = int(config["targets"]["deployment_targets"])
        self.evidence: list[dict[str, Any]] = []
        self.memo: dict[tuple[str, str, int], list[dict[str, Any]]] = {}

    def selected_instances(self, instances: list[SecurityInstance]) -> list[SecurityInstance]:
        if self.include_unbounded_sensitivity:
            return instances
        return [instance for instance in instances if not instance.sensitivity]

    def prime_current_components(self, profiles: list[str]) -> None:
        definitions: dict[tuple[str, str, int], list[SecurityInstance]] = {}
        for profile in profiles:
            main_kind, offline_kind = profile_kinds(profile)
            main_dimension = current_dimension(self.config, "main", main_kind)
            offline_dimension = current_dimension(self.config, "offline", offline_kind)
            definitions[("main", main_kind, main_dimension)] = self.selected_instances(
                main_instances(self.config, main_kind, main_dimension)
            )
            definitions[("offline", offline_kind, offline_dimension)] = self.selected_instances(
                offline_instances(self.config, offline_kind, offline_dimension)
            )
        common_key = ("common", "bfv", self.config["parameters"]["fhe"]["ring_degree"])
        definitions[common_key] = common_instances(self.config)

        pending = {key: value for key, value in definitions.items() if key not in self.memo}
        if not pending:
            return
        owner = {
            instance.instance_id: key
            for key, instances in pending.items()
            for instance in instances
        }
        all_instances = [instance for instances in pending.values() for instance in instances]
        if self.verbose:
            print(
                f"estimating {len(all_instances)} distinct current primitives ...",
                file=sys.stderr,
                flush=True,
            )
        results = self.runner.estimate_both(all_instances, self.method, self.deployments)
        for key in pending:
            self.memo[key] = []
        for result in results:
            self.memo[owner[result["instance"]["instance_id"]]].append(result)
        self.evidence.extend(results)

    def evaluate_component(self, stage: str, kind: str, dimension: int) -> list[dict[str, Any]]:
        key = (stage, kind, dimension)
        if key not in self.memo:
            factory: Callable[[dict[str, Any], str, int], list[SecurityInstance]]
            factory = main_instances if stage == "main" else offline_instances
            instances = self.selected_instances(factory(self.config, kind, dimension))
            if self.verbose:
                print(f"estimating {stage}/{kind}/{dimension} ...", file=sys.stderr, flush=True)
            self.memo[key] = self.runner.estimate_both(instances, self.method, self.deployments)
            self.evidence.extend(self.memo[key])
        return self.memo[key]

    def evaluate_common(self) -> list[dict[str, Any]]:
        key = ("common", "bfv", self.config["parameters"]["fhe"]["ring_degree"])
        if key not in self.memo:
            self.memo[key] = self.runner.estimate_both(
                common_instances(self.config), self.method, self.deployments
            )
            self.evidence.extend(self.memo[key])
        return self.memo[key]

    def component_passes(self, stage: str, kind: str, dimension: int, role: str) -> bool:
        results = self.evaluate_component(stage, kind, dimension)
        selected = [item for item in results if item["estimator_role"] == role]
        return bool(selected) and all(result_passes(item, self.target) for item in selected)

    def minimum(
        self, stage: str, kind: str, role: str, runtime_only: bool = False
    ) -> int | None:
        # Candidates are deliberately checked in ascending order.  We do not
        # assume that estimator output is perfectly monotone around a BKZ jump.
        for dimension in candidate_values(self.config, stage, kind, runtime_only=runtime_only):
            if self.component_passes(stage, kind, dimension, role):
                return dimension
        return None

    def component_summary(self, stage: str, kind: str, dimension: int) -> dict[str, Any]:
        results = self.evaluate_component(stage, kind, dimension)
        summary: dict[str, Any] = {"dimension": dimension}
        for role in ("paper", "modern"):
            selected = [item for item in results if item["estimator_role"] == role]
            valid = [item for item in selected if item.get("effective_rop_bits") is not None]
            weakest = min(valid, key=lambda item: item["effective_rop_bits"]) if valid else None
            summary[role] = {
                "status": "pass"
                if selected and all(result_passes(item, self.target) for item in selected)
                else "fail",
                "minimum_bits": weakest["effective_rop_bits"] if weakest else None,
                "weakest_primitive": weakest["instance"]["primitive"] if weakest else None,
                "weakest_attack": weakest.get("weakest_attack") if weakest else None,
                "complete": bool(selected)
                and all(
                    item.get("status") == "ok" and item.get("complete_attack_suite", True)
                    for item in selected
                ),
            }
        summary["conditional"] = any(item["instance"]["conditional"] for item in results)
        return summary


def fmt_bits(value: float | None) -> str:
    return "ERR" if value is None else f"{value:.1f}"


def status_for(
    method: str,
    correctness: dict[str, Any],
    main: dict[str, Any],
    offline: dict[str, Any],
    common: dict[str, Any],
) -> str:
    components = (main, offline, common)
    definitive_failure = correctness["status"] != "pass" or any(
        item[role]["status"] == "fail" and item[role]["minimum_bits"] is not None
        for item in components
        for role in ("paper", "modern")
    )
    if definitive_failure:
        return "SCREEN-FAIL" if method == "rough" else "FAIL"
    complete = all(item["paper"]["complete"] and item["modern"]["complete"] for item in components)
    passed = all(
        item[role]["status"] == "pass" for item in components for role in ("paper", "modern")
    ) and correctness["status"] == "pass"
    conditional = main.get("conditional", False) or offline.get("conditional", False)
    if not complete:
        return "INCONCLUSIVE"
    if method == "rough":
        return "SCREEN-PASS" if passed else "SCREEN-FAIL"
    if not passed:
        return "FAIL"
    return "PASS-CONDITIONAL" if conditional else "PASS"


def profile_report(audit: Audit, profile: str, select_parameters: bool) -> dict[str, Any]:
    main_kind, offline_kind = profile_kinds(profile)
    current_main = current_dimension(audit.config, "main", main_kind)
    current_offline = current_dimension(audit.config, "offline", offline_kind)
    main = audit.component_summary("main", main_kind, current_main)
    offline = audit.component_summary("offline", offline_kind, current_offline)

    common_results = audit.evaluate_common()
    common: dict[str, Any] = {"dimension": audit.config["parameters"]["fhe"]["ring_degree"]}
    for role in ("paper", "modern"):
        selected = [item for item in common_results if item["estimator_role"] == role]
        weakest = min(
            (item for item in selected if item.get("effective_rop_bits") is not None),
            key=lambda item: item["effective_rop_bits"],
            default=None,
        )
        common[role] = {
            "status": "pass"
            if selected and all(result_passes(item, audit.target) for item in selected)
            else "fail",
            "minimum_bits": weakest["effective_rop_bits"] if weakest else None,
            "weakest_primitive": weakest["instance"]["primitive"] if weakest else None,
            "weakest_attack": weakest.get("weakest_attack") if weakest else None,
            "complete": bool(selected)
            and all(
                item.get("status") == "ok" and item.get("complete_attack_suite", True)
                for item in selected
            ),
        }
    common["conditional"] = False

    if select_parameters:
        paper_minimum = {
            "main": audit.minimum("main", main_kind, "paper"),
            "offline": audit.minimum("offline", offline_kind, "paper"),
        }
        modern_minimum = {
            "main": audit.minimum("main", main_kind, "modern"),
            "offline": audit.minimum("offline", offline_kind, "modern"),
        }
        runtime_minimum = {
            "main": audit.minimum("main", main_kind, "modern", runtime_only=True),
            "offline": audit.minimum("offline", offline_kind, "modern", runtime_only=True),
        }
    else:
        paper_minimum = {"main": None, "offline": None}
        modern_minimum = {"main": None, "offline": None}
        runtime_minimum = {"main": None, "offline": None}
    correctness = correctness_analysis(audit.config)
    status = status_for(audit.method, correctness, main, offline, common)
    return {
        "profile": profile,
        "kinds": {"main": main_kind, "offline": offline_kind},
        "current": {"main": current_main, "offline": current_offline},
        "current_estimates": {"main": main, "offline": offline, "common": common},
        "minimum_in_candidate_set": {
            "paper_equivalent": paper_minimum,
            "modern": modern_minimum,
            "runtime_supported_modern": runtime_minimum,
        },
        "correctness": correctness,
        "status": status,
        "qualification": (
            "generic scalar SIS estimate; a structured Ring/Module-SIS reduction or audit remains required"
            if main.get("conditional")
            else (
                "RLWE coefficient-embedding estimate for the offline transform; no new SIS instance"
                if offline_kind == "ring"
                else "standard concrete LWE/SIS estimates under the stated model"
            )
        ),
    }


def write_report(output: Path, report: dict[str, Any], evidence: list[dict[str, Any]]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    (output / "evidence.json").write_text(
        json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    lines = [
        "# Security evaluation",
        "",
        f"Generated: {report['generated_at']}",
        f"Configuration: `{report['configuration']}`",
        f"Estimator mode: `{report['method']}`",
        "",
        "| Profile | Current (main/offline) | Paper bits | Modern bits | Correctness | Status |",
        "|---|---:|---:|---:|---:|---|",
    ]
    notes: list[str] = []
    for item in report["profiles"]:
        estimates = item["current_estimates"]
        paper_values = [
            estimates[part]["paper"]["minimum_bits"]
            for part in ("main", "offline", "common")
            if estimates[part]["paper"]["minimum_bits"] is not None
        ]
        modern_values = [
            estimates[part]["modern"]["minimum_bits"]
            for part in ("main", "offline", "common")
            if estimates[part]["modern"]["minimum_bits"] is not None
        ]
        paper = min(paper_values) if paper_values else None
        modern = min(modern_values) if modern_values else None
        lines.append(
            f"| {item['profile']} | {item['current']['main']}/{item['current']['offline']} "
            f"| {fmt_bits(paper)} | {fmt_bits(modern)} | {item['correctness']['status']} "
            f"| {item['status']} |"
        )
        if report["mode"] == "select":
            notes.append(
                f"- Candidate-set minima: `{json.dumps(item['minimum_in_candidate_set'], sort_keys=True)}`"
            )
        notes.append(f"- `{item['profile']}` qualification: {item['qualification']}")
    lines.extend(["", *notes])
    if report.get("bfv_attack_profile") == "decisive-usvp":
        lines.extend(
            [
                "",
                "BFV used the decisive-uSVP profile. A sub-target attack proves failure; "
                "an above-target result would remain inconclusive until `--bfv-full-suite` completes.",
            ]
        )
    lines.extend(
        [
            "",
            "`PASS-CONDITIONAL` is not a cryptographic audit: the Ring/Module-SIS scalar estimate "
            "does not replace a reduction for the exact structured construction.",
            "",
        ]
    )
    (output / "report.md").write_text("\n".join(lines), encoding="utf-8")


def print_table(report: dict[str, Any], report_path: Path) -> None:
    selecting = report["mode"] == "select"
    suffix = "  MIN-PAPER   MIN-MODERN  MIN-RUNTIME" if selecting else ""
    print("PROFILE          CURRENT(m/o)  PAPER   MODERN  CORRECT  STATUS" + suffix)
    for item in report["profiles"]:
        estimates = item["current_estimates"]

        def weakest(role: str) -> float | None:
            values = [
                estimates[part][role]["minimum_bits"] for part in ("main", "offline", "common")
            ]
            finite = [value for value in values if value is not None]
            return min(finite) if finite else None

        line = (
            f"{item['profile']:<16} {item['current']['main']:>5}/{item['current']['offline']:<5}     "
            f"{fmt_bits(weakest('paper')):>6}  {fmt_bits(weakest('modern')):>6}  "
            f"{item['correctness']['status'].upper():>7}  {item['status']}"
        )
        if selecting:
            minima = item["minimum_in_candidate_set"]

            def pair(label: str) -> str:
                value = minima[label]
                return f"{value['main'] or '-'}/{value['offline'] or '-'}"

            line += f"  {pair('paper_equivalent'):>11}  {pair('modern'):>11}  {pair('runtime_supported_modern'):>11}"
        print(line)
    print(f"report={report_path}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--profiles", default="all")
    parser.add_argument("--method", choices=("full", "rough"), default="full")
    parser.add_argument("--mode", choices=("audit", "select", "derive"), default="select")
    parser.add_argument("--from-current-source", action="store_true")
    parser.add_argument(
        "--include-unbounded-sensitivity",
        action="store_true",
        help="also estimate hypothetical unlimited main/offline samples",
    )
    parser.add_argument(
        "--bfv-full-suite",
        action="store_true",
        help="run every BFV attack; a pass requires this and it may take over an hour",
    )
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    try:
        config = load_config(args.config.resolve())
        if args.from_current_source:
            config = config_from_current_source(config, project_root)
        profiles = parse_profiles(args.profiles, config.get("profiles", list(PROFILES)))
        correctness = correctness_analysis(config)
        default_output = project_root / "native/results/security" / (
            dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        )
        output = (args.output or default_output).resolve()

        if args.mode == "derive":
            derived = {
                "configuration": str(args.config.resolve()),
                "database_size": human_binary_size(logical_database_bytes(config)),
                "database": config["database"],
                "parameters": config["parameters"],
                "targets": config["targets"],
                "honest_h_sis_bound": honest_h_sis_bound(config),
                "correctness": correctness,
                "runtime_source": config.get("runtime_source"),
                "profiles": [
                    {
                        "profile": profile,
                        "kinds": dict(zip(("main", "offline"), profile_kinds(profile))),
                        "current": {
                            stage: current_dimension(config, stage, kind)
                            for stage, kind in zip(("main", "offline"), profile_kinds(profile))
                        },
                    }
                    for profile in profiles
                ],
            }
            output.mkdir(parents=True, exist_ok=True)
            (output / "derived.json").write_text(
                json.dumps(derived, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            print(
                f"database={derived['database_size']} correctness={correctness['status']} "
                f"output={output / 'derived.json'}"
            )
            return 0 if correctness["status"] == "pass" else 2

        runner = EstimatorRunner(
            project_root,
            timeout_seconds=int(config.get("estimator_timeout_seconds", 1800)),
            parallel_jobs=int(config.get("estimator_parallel_jobs", 1)),
            bfv_attack_profile=(
                "full"
                if args.bfv_full_suite
                else config.get("fhe_attack_profile", "decisive-usvp")
            ),
        )
        runner.check_environment()
        audit = Audit(
            config,
            runner,
            args.method,
            args.verbose,
            args.include_unbounded_sensitivity,
        )
        audit.prime_current_components(profiles)
        reports = [profile_report(audit, profile, args.mode == "select") for profile in profiles]
        report = {
            "schema_version": 1,
            "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
            "configuration": str(args.config.resolve()),
            "database_size": human_binary_size(logical_database_bytes(config)),
            "method": args.method,
            "mode": args.mode,
            "include_unbounded_sensitivity": args.include_unbounded_sensitivity,
            "bfv_attack_profile": runner.bfv_attack_profile,
            "targets": config["targets"],
            "input": config,
            "host": {"platform": platform.platform(), "sage": shutil.which("sage")},
            "estimator_provenance": runner.provenance(),
            "profiles": reports,
        }
        write_report(output, report, audit.evidence)
        print_table(report, output / "report.md")
        statuses = {item["status"] for item in reports}
        return 0 if statuses <= {"PASS", "PASS-CONDITIONAL", "SCREEN-PASS"} else 2
    except (ConfigError, EstimatorError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
