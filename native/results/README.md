# Generated results

Run `make paper-summarize SESSION_ID=matrix-...` after a complete matrix session.
The output under `native/results/paper-v1/` contains:

| File | Contents |
|---|---|
| `runs.csv` | One row per successful native run |
| `summary.csv` | Mean, sample standard deviation, median, range and 95% Student-t interval |
| `speedups.csv` | Ratios of means and repetition-paired same-host speedups |
| `comparison-small-client.csv` | Qualified source-paper reference values |
| `manifest.json` | Hashes of input logs, paper manifest and baseline transcription |

Raw logs and schedules are stored under `native/logs/`. The summarizer rejects
incomplete sessions, mismatched hashes, schedule/log disagreements and missing
correctness markers. Generated outputs are ignored by Git.

The primary baseline is the same-host `dense` profile. Source-paper comparisons
are secondary cross-hardware references. Source values cover 256 MiB, 512 MiB
and 1 GiB; 2 GiB and 4 GiB remain `not-reported-by-source`.

Security output formats are described in [the security README](../security/README.md).
