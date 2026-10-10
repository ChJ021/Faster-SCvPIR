# Native Small-Client vPIR paper-v1 experiment

The native path pins the authors' `Verifiable-Hintless-PIR` proof of concept and
adds exact negacyclic NTT preprocessors for the main hint and offline
`H_2 = D^T A_2`. It targets a single-process static-database experiment under
an honest, externally authenticated hint.

All shell examples below run from the repository root. See the root
[README](../README.md) for setup, security scope, and artifact availability.
Archived logs and reports mentioned here are local artifacts excluded from Git.

## Reproducible source boundary

| Item | Frozen value |
|---|---|
| Upstream | `https://github.com/mayank0403/Verifiable-Hintless-PIR.git` |
| Commit | `56b8b744276aa3f3c078509501200967d28cfc7b` |
| Bazel | 6.5.0, project-local |
| Compiler mode | Clang, C++17, `-c opt` |
| Main structured degree | 2048 |
| Offline structured degree | 4096 (`smoke`: 2048) |
| BFV degree | 4096 |

`scripts/prepare-upstream.sh` verifies the source-patch checksum, checks out the
pinned commit, applies the complete patch and prepares the pinned Eigen archive.
The runner requires the checkout to be exactly the reverse application of that
patch; arbitrary upstream edits are rejected.

The source now retains the upstream-compatible 2 MiB default but accepts a
runtime `--database-profile`. Paper scripts therefore never use `sed` to change
tracked C++ constants and one binary can execute every database shape.

## Frozen database layouts

| Profile | Rows | Columns | Record bits | Stack | Main blocks | Offline blocks |
|---|---:|---:|---:|---:|---:|---:|
| 256 MiB | 16384 | 16384 | 8 | 256 | 8 | 4 |
| 512 MiB | 32768 | 16384 | 8 | 8 | 8 | 8 |
| 1 GiB | 32768 | 32768 | 8 | 1 | 16 | 8 |
| 2 GiB | 65536 | 32768 | 8 | 32 | 16 | 16 |
| 4 GiB | 65536 | 65536 | 8 | 1 | 32 | 16 |

The first three shapes reproduce Appendix A.5 of the source paper. The 2/4 GiB
profiles continue its near-square convention with one-byte cells. They are new
same-host scaling points, not reported source-paper measurements.

All dimensions, cryptographic values, memory gates and claim labels are defined
in `manifests/paper-v1.json` and protected by `paper-v1.sha256`.

## Preprocessing ablations

| Canonical profile | Main hint | Offline H2 | Legacy alias |
|---|---|---|---|
| `dense` | dense LWE | dense LWE | `baseline` |
| `negacyclic-main` | exact NTT | dense LWE | `ypir-main` |
| `negacyclic-offline` | dense LWE | exact NTT | `distpir-offline` |
| `negacyclic-both` | exact NTT | exact NTT | `hybrid` |

Only the canonical profile is written to new logs. Structured-main results are
marked `screen-pass-conditional-on-paper-reduction`; this accurately separates
the concrete estimator screen from the manuscript's Ring/Module-SIS argument.

The old sufficient-inequality diagnostic can be false even when the complete
estimator screen passes. It is retained as
`legacy_offline_sis_sufficient_bound=not_met`, without the misleading word
`ERROR`, and points to the frozen estimator evidence.

## Single-cell runner

```bash
native/scripts/build-run-paper.sh \
  --size=2gib \
  --preproc-profile=negacyclic-both \
  --query-index=32764
```

Compatibility entrypoints exist for all five formal sizes:

```bash
native/scripts/build-run-paper-256mib.sh --preproc-profile=dense
native/scripts/build-run-paper-512mib.sh --preproc-profile=dense
native/scripts/build-run-paper-1gib.sh --preproc-profile=negacyclic-main
native/scripts/build-run-paper-2gib.sh --preproc-profile=negacyclic-offline
native/scripts/build-run-paper-4gib.sh --preproc-profile=negacyclic-both
```

Useful modes are `--dry-run`, `--prepare-only`, `--build-only` and
`--skip-build`. The last is used by the matrix scheduler only after a successful
shared build. `--run-id` never overwrites an existing directory.

Runtime memory gates are:

| Size | Minimum | Recommended |
|---|---:|---:|
| 256 MiB | 8 GiB | 12 GiB |
| 512 MiB | 12 GiB | 16 GiB |
| 1 GiB | 20 GiB | 32 GiB |
| 2 GiB | 32 GiB | 40 GiB |
| 4 GiB | 52 GiB | 60 GiB |

`PIR_ALLOW_LOW_MEMORY=1` is an explicit OOM/swap-risk override. It is recorded
in the context. The runner does not modify host settings.

## Balanced formal runs

The scheduler requires an explicit repetition count and seed:

```bash
native/scripts/run-paper-matrix.sh \
  --sizes=256mib,512mib,1gib,2gib,4gib \
  --profiles=dense,negacyclic-main,negacyclic-offline,negacyclic-both \
  --repetitions=5 \
  --order-seed=20260909 \
  --cpu-set=2
```

It constructs a seeded balanced Latin rotation, gives all four profiles in one
size/repetition the same deterministic stack-aligned query, records the full
schedule before starting, builds once, stops on failure and supports
`--resume PATH`. Formal mode requires an explicit fixed CPU affinity and a
performance CPU governor; use `--allow-unstable-cpu` only when the resulting
qualification is acceptable. Because this implementation and the source-paper
implementation are single-threaded, a single logical CPU is the recommended
affinity; keep its SMT sibling idle.

Logs are stored below:

```text
logs/paper-v1/<size>/<profile>/<run-id>/
  context-before.txt
  context-after.txt
  metadata.txt
  run.log
  run.time.txt
  vmstat.log
```

Each run records source, patch, manifest and binary hashes along with database
shape, query, backends, security-status labels, host details, compiler, memory,
governor and affinity.

## Result aggregation

```bash
native/scripts/summarize-paper-results.sh --session-id=matrix-YYYYMMDDTHHMMSSZ
```

The parser fails on an incomplete schedule, a schedule/manifest mismatch,
missing metadata, missing timing stages, incorrect hashes or absent correctness
markers. It writes `runs.csv`, `summary.csv`, `speedups.csv`,
`comparison-small-client.csv` and `manifest.json` to a new non-overwriting
result directory. `speedups.csv` includes both the ratio of means and
repetition-paired speedups with 95% Student-t intervals. Manually launched smoke
runs require the explicit diagnostic-only option `--allow-unscheduled`.

Same-host dense speedups are the primary evidence. Source-paper values in
`baselines/small-client-vpir-paper.json` are labeled cross-hardware references;
2/4 GiB remain explicitly unreported by that paper.

## Security and correctness checks

```bash
python3 -m unittest discover -s native/experiments/tests -v
python3 -m unittest discover -s native/security/tests -v
native/scripts/run-bfv-parameter-test.sh
native/scripts/run-security-audit.sh \
  --config native/security/configs/4gib.json \
  --mode derive --profiles all
```

`security/configs/2gib.json` and `4gib.json` use the near-square layouts. Source
inspection freezes cryptographic constants but no longer overwrites the
size-specific database shape, because that shape is selected at runtime.

The dedicated BFV target validates the per-response-block operation. The
number of response blocks is recorded for larger layouts; this repository does
not claim that empirical testing replaces an analytic correctness proof.
