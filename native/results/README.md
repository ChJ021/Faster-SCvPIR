# Curated experiment results

No raw experiment result is published yet. Existing runs, failed attempts,
duplicates, build caches, and lock files remain local and are intentionally
excluded from GitHub.

> **Validity warning:** these runs predate two main-pad sampling fixes: a
> full-width `uint32_t(1) << 32` mask was replaced by an explicit all-ones
> branch, and Eigen row population now uses
> `output.row(i) = buffer.transpose()`. Under the recorded optimized build, the
> old code produced an all-zero main public pad. Those local files are only
> historical timing/provenance records; they are neither security-valid nor
> post-fix performance results. New experiments must be collected after both
> fixes before any raw results are added here.

Future published runs should retain `run.log`, `/usr/bin/time` statistics,
sampled `vmstat` data, metadata, and the before/after execution context.

The preprocessing modes are:

- `baseline`: dense main Hint and dense offline H2.
- `ypir-main`: exact negacyclic NTT for the main Hint only.
- `distpir-offline`: dense main Hint and exact negacyclic NTT for H2.
- `hybrid`: exact negacyclic NTT for both preprocessing computations.
