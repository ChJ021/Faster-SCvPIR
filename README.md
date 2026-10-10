# Faster-SCvPIR

Structured preprocessing acceleration for Small-Client verifiable PIR (SCvPIR),
with a conditional security analysis.

This repository contains the native C++ integration, frozen experiment
parameters, four-profile benchmark harness, and security-assessment scripts.
It builds on [Verifiable PIR with Small Client Storage](https://eprint.iacr.org/2025/1714)
and the authors' [Verifiable-Hintless-PIR implementation](https://github.com/mayank0403/Verifiable-Hintless-PIR).
The upstream source is reconstructed from a pinned commit and a checked patch.

## What changes

Stacked negacyclic matrices and exact number-theoretic transforms (NTTs) are
used consistently in five pad-dependent products:

- Main hint generation: `H = D A`.
- Query preparation: `A s`.
- Registration verification: `Z' A`.
- Offline hint generation: `H_2 = D^T A_2`.
- Offline challenge encryption: `A_2 s_j`.

The subsequent linear checks retain their form. The selected structured
parameters change the secret dimensions and hint sizes; the retrieval scan
`D u` remains unchanged.

| Profile | Main pad | Offline pad |
|---|---|---|
| `dense` | Dense | Dense |
| `negacyclic-main` | Negacyclic / exact NTT | Dense |
| `negacyclic-offline` | Dense | Negacyclic / exact NTT |
| `negacyclic-both` | Negacyclic / exact NTT | Negacyclic / exact NTT |

## Scope and reported results

The evaluated configuration assumes **honestly generated hints**, with any
external authentication outside this proof of concept. It is a single-process,
static-database experiment; it does not provide a network service.

The manuscript reports five database layouts from 256 MiB to 4 GiB, four
profiles, and five repetitions per layout/profile on the same host
(Intel Core i7-10700, 64 GB RAM, Ubuntu 22.04.5, single-threaded execution).

| Metric | Reported Dense-to-structured comparison |
|---|---|
| Total preprocessing, including one client registration | 6.69–14.17× speedup |
| Combined query preparation and retrieval computation | 3.91–7.08× speedup |
| Compressed-proof payload | Unchanged |
| Combined server hints, `H + H_2` | 45.5% larger |

These are computation measurements excluding network transmission. Retrieval
alone is essentially unchanged; the query-path benefit comes from preparation.
The compressed-proof payload is only one part of client storage.

The analysis establishes algebraic identities and a bounded Ring-SIS binding
relation, then adapts SCvPIR's simulation under explicit assumptions. In
particular, hidden-challenge transfer (H), delegation feedback (F), and the
extraction budget remain conditions. The evaluated parameters do not instantiate
the arbitrary-malicious-hint theorem. Lattice-estimator outputs assess the
declared attack-cost model; they do not prove these protocol requirements.
See [the security-model notes](native/security/MODEL_README.md).

## Get the repository

```bash
git clone https://github.com/ChJ021/Faster-SCvPIR.git
cd Faster-SCvPIR
```

All commands below run from the repository root.

### Prerequisites

- Linux x86-64; the recorded performance environment is Ubuntu 22.04.5.
- Python 3.10 or newer, GNU Make, Bash, Git, and standard Linux utilities.
- For native builds: Clang with C++17 support, unzip, pkg-config, and the
  upstream system dependencies, including OpenSSL and GSL development headers.
  The pinned upstream Dockerfile lists its build dependencies.
- Bazel 6.5.0 and the pinned Eigen archive are included under
  `native/tools/` and `native/toolchain/sources/`.
- SageMath **9.5** is required for lattice-estimator runs, but not for the
  Python unit tests.
- Network access is needed to fetch the pinned upstream, Bazel dependencies,
  and estimator snapshots on first use.

### Lightweight validation

These checks do not run the full performance experiment:

```bash
export PYTHONDONTWRITEBYTECODE=1
make check
python3 -m unittest discover -s native/security -p test_model_audit.py -v
make paper-dry-run
```

The dry run resolves all 20 layout/profile combinations and writes a schedule
under the ignored `native/logs/` directory.

### Prepare and verify the native source

```bash
native/scripts/prepare-upstream.sh
make native-verify
```

Preparation checks the source-patch hash, checks out upstream commit
`56b8b744276aa3f3c078509501200967d28cfc7b`, applies the patch, and unpacks
the pinned Eigen archive. Verification checks the source state and toolchain.

### Build and run

```bash
make paper-build SIZE=1gib PROFILE=dense
make paper-run SIZE=1gib PROFILE=negacyclic-both
```

The shared binary accepts all frozen layouts at runtime. For a small
non-paper diagnostic run, use the paper runner's 4 MiB smoke profile:

```bash
make paper-run SIZE=smoke PROFILE=negacyclic-both
```

This differs from the original upstream's 2 MiB default used by
`make native-smoke`.

| Paper layout | Minimum available memory | Recommended available memory |
|---|---:|---:|
| 256 MiB | 8 GiB | 12 GiB |
| 512 MiB | 12 GiB | 16 GiB |
| 1 GiB | 20 GiB | 32 GiB |
| 2 GiB | 32 GiB | 40 GiB |
| 4 GiB | 52 GiB | 60 GiB |

### Run the full experiment matrix

```bash
make paper-matrix REPETITIONS=5 ORDER_SEED=20260909 CPU_SET=2
```

This schedules 100 runs with balanced profile ordering and a common query
index within each layout/repetition. Select a logical CPU available on your
machine. Formal runs enforce CPU affinity, memory gates, and the performance
governor policy; the scripts do not change host settings.

To aggregate a completed session, replace `matrix-...` with the session ID
printed by the scheduler:

```bash
make paper-summarize SESSION_ID=matrix-...
```

The summarizer validates schedules, metadata, hashes, timing stages, and
correctness markers before writing per-run CSVs, summaries, speedups, and an
input manifest. See [native experiment details](native/README.md) and
[the result policy](native/results/README.md).

## Security estimates and BFV checks

After preparing the native source and installing SageMath 9.5:

```bash
make security-setup
python3 native/security/model_audit.py \
  --cache native/cache/security --project-root . \
  --output native/results/security/paper-model-rerun --jobs 8
PIR_BFV_TEST_RUNS=10 native/scripts/run-bfv-parameter-test.sh
```

Choose a **new output directory** for every model-audit run. The fixed-model
assessment is classical and single-target, with explicit attack selections and
cost conventions. Its reported minimum is 128.14 bits after rounding down;
this is separate from the statistical verification bound.

The BFV test checks a specific response-block workload. Passing it does not
replace a correctness proof or validate every database/profile combination.
The older `make security-audit` interface is a separate assessment path,
not an alias for the manuscript's fixed-model audit.

## Repository contents and artifact availability

| Path | Contents |
|---|---|
| `native/patches/` | Complete patch against the pinned upstream |
| `native/manifests/` | Frozen paper parameters, checksums, and upstream lock |
| `native/experiments/` | Configuration, scheduling, parsing, and tests |
| `native/scripts/` | Source preparation, builds, runs, and assessment entrypoints |
| `native/security/` | Estimator configuration, drivers, tests, and model notes |
| `native/baselines/` | Source-paper values for qualified cross-hardware reference |
| `native/tools/`, `native/toolchain/` | Pinned Bazel binary and Eigen archive |
| `docs/UPSTREAMS.md` | Source provenance and upstream license information |

**The Git checkout does not contain the archived paper logs or generated
security reports.** Vendored sources, caches, build outputs, raw logs, and
generated report directories are excluded by `.gitignore`. Reproduction
commands populate these paths locally.

Historical paths mentioned in the detailed documentation, such as
`native/results/security/paper-model-20260916/`, identify evidence retained
on the experiment machine; they are not downloadable files in this checkout.
The frozen manifest also records hashes of historical security evidence.
Those records are provenance references, not evidence bundled by this Git push.

Do not relabel older measurements with a new manifest or overwrite historical
evidence. New executions receive new schedules, logs, and output directories.

## Attribution

The protocol framework comes from Rathee, Lee, and Popa's SCvPIR work.
Structured hint generation follows the negacyclic/NTT approach used by
[YPIR](https://github.com/menonsamir/ypir). This repository integrates the
structured path across SCvPIR's coupled products and provides the experiment
harness described above.

Upstream components retain their original license notices. See
[upstream provenance](docs/UPSTREAMS.md) for the BSD, MIT, and Apache-2.0
components.
