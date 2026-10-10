# Security reproduction

The current manuscript uses the fixed-model assessment documented in
`MODEL_README.md`. From the project root:

```bash
python3 native/security/model_audit.py \
  --cache native/cache/security --project-root . \
  --output native/results/security/paper-model-rerun --jobs 8
python3 -m unittest discover -s native/security -p test_model_audit.py -v
PIR_BFV_TEST_RUNS=10 native/scripts/run-bfv-parameter-test.sh
```

Use a new output directory for each run. SageMath 9.5 and pinned estimator
sources/archives are retained. Current evidence is in
`native/results/security/paper-model-20260916/report.json` and its
`bfv_validation/` directory. The full report embeds all requests and results;
the redundant individual request/result JSON files have been archived.

The older CLI, calibration code, model checks and pinned control estimator
remain available for parameter validation. Their old result caches and obsolete
uSVP-only screens were moved to the sibling archive; they are not inputs to
the current model audit. `make security-audit` retains its original, more
general assessment semantics; it is not an alias for the current model audit.

The frozen paper manifest still references
`native/results/security/validation-1gib-all/evidence.json`, which remains at
its original path with its original hash. Do not remove that file without
explicitly migrating the frozen manifest and provenance.

The pre-cleanup documentation and older evidence remain recoverable from:
`/home/user/small-client-pir-archive-20260916T084017Z/files/native/security/`.
