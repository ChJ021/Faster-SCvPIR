# Faster-SCvPIR

Negacyclic/NTT preprocessing acceleration for
[Small-Client verifiable PIR](https://eprint.iacr.org/2025/1714).
This repository contains the native integration, fixed experiment parameters,
benchmark scripts and security-model assessment.

| Profile | Main pad | Offline pad |
|---|---|---|
| `dense` | Dense | Dense |
| `negacyclic-main` | Negacyclic / exact NTT | Dense |
| `negacyclic-offline` | Dense | Negacyclic / exact NTT |
| `negacyclic-both` | Negacyclic / exact NTT | Negacyclic / exact NTT |

The experiment uses honestly generated hints and a static database in one
process. External hint authentication and network transmission are outside its
scope. The security analysis remains conditional on hidden-challenge transfer
(H), delegation feedback (F), and the extraction budget. Parameter estimates do
not prove these protocol assumptions.

## Requirements

- Linux x86-64, Python 3.10+, GNU Make, Bash, Git and standard Linux utilities.
- Native builds: Clang with C++17 support, unzip, pkg-config, OpenSSL and GSL
  development headers; see the pinned upstream Dockerfile for system packages.
- Bazel 6.5.0 and Eigen 3.4.0 are included in `native/tools/` and
  `native/toolchain/sources/`.
- Security estimates additionally require SageMath **9.5**.
- First-time preparation and builds require network access for dependencies.

## Check and prepare

Run all commands from the repository root:

```bash
make check
make paper-dry-run
native/scripts/prepare-upstream.sh
make native-verify
```

`make check` validates the manifest and runs Python unit tests without SageMath
or native builds. The dry run writes a schedule for all 20 layout/profile
combinations without executing experiments. Source preparation reconstructs the
pinned upstream with the checked patch and Eigen archive.

## Performance experiment

```bash
make paper-build
make paper-run SIZE=smoke PROFILE=negacyclic-both
make paper-matrix REPETITIONS=5 ORDER_SEED=20260909 CPU_SET=2
make paper-summarize SESSION_ID=matrix-...
```

The smoke layout is 4 MiB. The formal matrix contains five database layouts,
four profiles and five repetitions (100 runs). Choose an available logical CPU
and use the session ID printed by the scheduler when summarizing. Formal runs
check memory, CPU affinity and the performance governor; scripts do not change
host settings. A single paper case can be run with
`make paper-run SIZE=1gib PROFILE=negacyclic-both CPU_SET=2`.

| Layout | Minimum available memory | Recommended available memory |
|---|---:|---:|
| 256 MiB | 8 GiB | 12 GiB |
| 512 MiB | 12 GiB | 16 GiB |
| 1 GiB | 20 GiB | 32 GiB |
| 2 GiB | 32 GiB | 40 GiB |
| 4 GiB | 52 GiB | 60 GiB |

`make native-env` records the build environment under `native/logs/`.
See [result formats](native/results/README.md) for aggregation and validation.

## Security assessment

After native source preparation and installation of SageMath 9.5:

```bash
make security-setup
make security-model SECURITY_OUTPUT=native/results/security/run-1
PIR_BFV_TEST_RUNS=10 make security-bfv-test
```

Use a new output directory for each assessment. See
[the security model](native/security/README.md) for attack selections, output
files and the scope of the BFV test.

## Files and attribution

- `native/manifests/`: paper parameters, checksums and upstream lock.
- `native/patches/`: native C++ integration patch.
- `native/experiments/`, `native/scripts/`: experiment drivers and tests.
- `native/security/`: security configurations, drivers and tests.
- `native/baselines/`: source-paper values for cross-hardware reference.

Generated sources, caches, logs and results are ignored by Git. Measured
performance data and generated security reports are not bundled; the commands
above produce new outputs locally. Each run records its manifest hash, and the
summarizer rejects mismatches.

The protocol framework and native implementation derive from Rathee, Lee and
Popa's [SCvPIR](https://github.com/mayank0403/Verifiable-Hintless-PIR).
Structured hint generation follows the negacyclic/NTT approach of
[YPIR](https://github.com/menonsamir/ypir). See
[upstream provenance and licenses](docs/UPSTREAMS.md).
