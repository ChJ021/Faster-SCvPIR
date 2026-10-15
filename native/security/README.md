# Security assessment

This is a classical, single-target assessment with a 128-bit target under a
specified attack-cost model. It does not prove the protocol's H/F assumptions,
public-seed security, evaluation-key/KDM security or arbitrary-malicious-hint
security.

## Run

From the repository root, after preparing the native source and installing
SageMath **9.5**:

```bash
make security-setup
make security-model SECURITY_OUTPUT=native/results/security/run-1 SECURITY_JOBS=8
PIR_BFV_TEST_RUNS=10 make security-bfv-test
```

The estimator driver requires a new output directory. It verifies the pinned
archive hashes and extracted estimator files, compares configured cryptographic
parameters with the native source, and records driver, worker and source hashes.
It writes `report.json` and individual `*.request.json` / `*.result.json` files
into `SECURITY_OUTPUT`. Estimator results are computed afresh.

The security unit tests are included in `make check`; `make security-test` runs
only those tests and requires neither SageMath nor a native build.

## Model

The five configurations under `configs/` cover seven components per layout,
with identical requests shared within an assessment:

- Dense LWE and BFV: estimator `162c505`, `LWE.estimate`, explicit MATZOV/GSA,
  and six lattice attacks: uSVP, BDD, BDD hybrid, BDD MITM hybrid, dual and
  dual hybrid.
- Structured RLWE: estimator `4195c66`, the same convention with its additional
  dual MITM hybrid attack.
- Binding: estimator `162c505`, `SIS.estimate.rough`, ADPS16 Core-SVP/LGSA.
  Structured binding uses a generic coefficient embedding.

BKW, Arora–Gröbner, quantum and ring-specific attacks, and multi-target loss are
outside this model. The SIS and LWE cost conventions differ. A missing, failed,
non-finite or timed-out declared attack produces `INCONCLUSIVE`; a pass is
reported only as `PASS-IN-MODEL`.

## BFV test

`make security-bfv-test` builds and runs the targeted native BFV test and prints
its summary. It covers packing, evaluation-key serialization, precomputed-pad
rotations and a dense 1 GiB BSGS response block using the fixed parameters.
It does not execute the complete PIR experiment matrix. Repeated targeted tests
do not establish a correctness proof, independent failure probabilities or
coverage of every structured layout. The printed Gaussian extrapolation is a
model estimate.

Estimator source: [Lattice Estimator](https://github.com/malb/lattice-estimator).
Snapshot checksums are pinned in `estimator.lock.sh`.
