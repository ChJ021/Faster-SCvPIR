# Fixed-model 128-bit parameter assessment (2026-09-16)

This is a **model-specific, classical, single-target** assessment, not a claim
against every attack or a proof of the protocol's additional assumptions.
The performance parameters were not changed.

## Result and model

`model_report.json` records 23 freshly evaluated distinct requests covering
seven components in each of five database layouts. All return `PASS-IN-MODEL`.
The minimum is BFV BDD at **128.14567466386998 bits**, conservatively reported
as **128.14 bits** in the manuscript. This leaves very little margin.

- LWE/RLWE/BFV: `LWE.estimate`, explicit `RC.MATZOV`, GSA, all six lattice
  attacks in `162c505`: uSVP, BDD, BDD hybrid, BDD MITM hybrid, dual, dual hybrid.
- Structured RLWE: YPIR reference `4195c66`, the same model plus its separately
  named dual MITM hybrid (seven lattice attacks).
- SIS: `162c505`, `SIS.estimate.rough`, ADPS16 Core-SVP and LGSA. This is not
  the MATZOV LWE cost convention. Structured binding uses a generic coefficient
  embedding, not a specialized Ring-SIS security proof.
- BKW, Arora–Gröbner, quantum/ring-specific attacks and multi-target loss are
  not assessed by this profile. Public-seed, feedback and evaluation-key/KDM
  assumptions remain separate. The main dense LWE instance has a pre-existing
  119.74-bit estimate under the different rough Core-SVP convention;
  `dense-main-rough-sensitivity.json` is retained, not discarded.
- A missing, infinite, timed-out or erroneous declared attack produces
  `INCONCLUSIVE`, never a pass. The pre-existing full-audit worker and its
  `complete_attack_suite` semantics have not been weakened.

## Reproduction on the server

From `/home/user/small-client-pir` (SageMath 9.5):

```bash
python3 native/security/model_audit.py \
  --cache native/cache/security --project-root . \
  --output native/results/security/paper-model-rerun --jobs 8
python3 -m unittest discover -s native/security -p test_model_audit.py -v
python3 -m unittest discover -s native/security/tests -v
PIR_BFV_TEST_RUNS=10 native/scripts/run-bfv-parameter-test.sh
```

Use a new output directory for each run. The driver verifies archive SHA-256
and compares every extracted estimator source file with the archive. It
also compares configured cryptographic constants with the native source and
records driver/worker/source hashes. Old estimator result caches are not used.
The current run is in `native/results/security/paper-model-20260916/`.
Runtime source parsing is inherited from `native/security/model.py`; the
distribution parameters are explicit frozen inputs, not inferred from a
security estimate. Main/BFV binomial variance 8 means estimator `eta=16`.

For reproduction outside the native project, copy this directory and the
pinned estimator cache, and omit `--project-root`:

```bash
python3 data/security_reproduction/model_audit.py \
  --cache /path/to/security-cache --output /tmp/pir-model-new-run
python3 -m unittest discover -s data/security_reproduction -p test_model_audit.py -v
python3 data/security_reproduction/bfv_validation/summarize.py
```

The local `model_report.json` contains complete requests and attack outputs
for each layout (including repeated requests) and exact configuration inputs.
The original `sage_worker.py` and `../security_estimates.json` remain archival;
the manuscript now uses `model_worker.py` and `model_report.json`.

## BFV correctness evidence

`bfv_validation/` contains the existing C++ test, shell wrapper, ten raw test
logs, their checksums and a verified summary. All ten targeted runs passed
with the performance moduli and gadget bases `[13,14]` (nine digits).
The minimum measured margin is 4.12 bits. Packing, evaluation-key round-trip,
precomputed-pad rotations and a complete dense 1-GiB BSGS response block are
tested. The test uses fixed plaintext/query and some fixed seeds: the runs
are not claimed to be independent statistical trials, and do not cover every
structured shape or replace the 100 archived end-to-end performance checks.
The printed Gaussian failure extrapolation is not treated as a rigorous
failure probability in the manuscript. `../lhe_noise_bounds.json` covers LHE only.

## Manuscript changes

- Main parameters: a concise fixed-model target, selection constraints and
  appendix pointer; no new protocol-wide security theorem.
- Appendix: one table of worst-layout component costs replaces the old 1-GiB
  comparison table and uSVP-only BFV entry. Layout inputs and LHE per-layout
  tables remain machine-readable rather than being repeated in the paper.
- Statistical verification, decoding checks and computational attack costs
  remain distinct. No performance measurement or protocol constant changed.

Reference implementation and model documentation:
[Lattice Estimator](https://github.com/malb/lattice-estimator).
