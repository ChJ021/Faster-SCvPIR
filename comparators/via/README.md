# VIA comparison adapter — version 1 placeholder

VIA is not part of the first Small-client vPIR security construction. This directory reserves its later native adapter and benchmark profile.

The current command

```bash
uv --cache-dir .uv-cache --offline run --python .venv/bin/python \
  python -m small_client_vpir benchmark --protocol via
```

returns the same reference-v0 top-level schema as the Small-client path, but with `status=not-integrated`, `comparison_ready=false`, and no fabricated measurements.

Before enabling results, the adapter must pin the official VIA artifact, reproduce its tests, expose database preprocessing/query/answer/recover boundaries, and report the same database geometry, record size, target security, hardware, thread count, warm-up policy, serialized bytes and peak memory as the Small-client implementation. See [`../../docs/VIA_COMPARISON.md`](../../docs/VIA_COMPARISON.md).
