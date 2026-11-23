# Faster-SCvPIR

Lean experiment tree for negacyclic/NTT preprocessing acceleration in
[Small-Client verifiable PIR](https://eprint.iacr.org/2025/1714).
It keeps the core protocol implementation and the machinery needed to run the
formal paper-v1 matrix; unit tests, source-marker verification and the separate
security-model assessment are not included.

| Profile | Main pad | Offline pad |
|---|---|---|
| `dense` | Dense | Dense |
| `negacyclic-main` | Negacyclic / exact NTT | Dense |
| `negacyclic-offline` | Dense | Negacyclic / exact NTT |
| `negacyclic-both` | Negacyclic / exact NTT | Negacyclic / exact NTT |

The experiment uses honestly generated hints and a static database in one
process. External hint authentication and network transmission are outside its
scope.

## Layout

```
hintless_simplepir/   PIR protocol, server/client, database, preprocessing backends
verisimplepir/        vPIR verification/proof layer
linpir/               RLWE/BFV delegation machinery
lwe/                  LWE types/encryption and exact negacyclic NTT
manifests/            Frozen paper-v1 sizes, profiles and cryptographic parameters
experiments/          Manifest resolution, matrix scheduling and result summarization
scripts/              Bash entry points and feature modules under scripts/lib/
baselines/            Source-paper reference values
toolchain/, tools/    Pinned Eigen archive and Bazel 6.5.0
```

The C++ experiment driver is `hintless_simplepir/pir_experiment.cc`, built as
`//hintless_simplepir:pir_experiment`.

## Requirements

- Linux x86-64 or aarch64, Python 3.10+, GNU Make, Bash, Git and standard Linux
  utilities.
- Native builds: Clang with C++17, unzip, pkg-config, OpenSSL and GSL
  development headers.
- The bundled Bazel binary is x86-64. On other architectures set `BAZEL_BIN` to
  a matching Bazel 6.5.0 executable.

## Run the experiment

```bash
make native-prepare        # unpack the pinned Eigen 3.4.0 archive
make paper-list            # show sizes and profiles
make paper-dry-run         # resolve the full matrix without running
make paper-build           # build the shared native binary
make paper-run SIZE=1gib PROFILE=negacyclic-both CPU_SET=2
make paper-matrix REPETITIONS=5 ORDER_SEED=20260909 CPU_SET=2
make paper-summarize SESSION_ID=matrix-...
```

Sizes, row/column layouts, record widths, stacking, ring degrees and memory
floors live in `manifests/paper-v1.json`; the manifest checksum is verified on
every run. The runner receives the geometry through `--db-rows`,
`--db-columns`, `--db-record-bits` and `--db-stack-cells`, so no C++ size table
needs to be kept in sync.

| Layout | Minimum available memory | Recommended available memory |
|---|---:|---:|
| 128 MiB | 2 GiB | 4 GiB |
| 256 MiB | 8 GiB | 12 GiB |
| 512 MiB | 12 GiB | 16 GiB |
| 1 GiB | 20 GiB | 32 GiB |
| 2 GiB | 32 GiB | 40 GiB |
| 4 GiB | 52 GiB | 60 GiB |

The matrix covers six database layouts, four profiles and the requested number
of repetitions (120 runs for five repetitions). Formal runs require an explicit
CPU set and the performance CPU governor; scripts never change host settings.
Memory checks are warning-only: `PIR_ALLOW_LOW_MEMORY=1` silences the
below-minimum warning and `PIR_SKIP_MEMORY_CHECK=1` skips measurement.

Raw logs are written under `logs/paper-v1/<SIZE>/<PROFILE>/<RUN_ID>/`, schedules
under `logs/paper-v1/schedules/`, and summarized CSV outputs under
`results/paper-v1/`. Generated state is ignored by Git.

## ARM64 / Raspberry Pi

```bash
export BAZEL_BIN="$(command -v bazel)"
bazel --version   # must report 6.5.0
```

Use `PIR_SCALAR=1` to compile Highway in scalar fallback mode. Timings measured
on ARM are not comparable with the paper's x86-64 reference values.

## Attribution

The protocol implementation derives from Rathee, Lee and Popa's SCvPIR
([Verifiable-Hintless-PIR](https://github.com/mayank0403/Verifiable-Hintless-PIR)).
Structured hint generation follows
[YPIR](https://github.com/menonsamir/ypir). See
[upstream provenance and licenses](docs/UPSTREAMS.md).
