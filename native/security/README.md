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
