# Exact-NTT offline H2 preprocessing overlay

Base upstream commit: `56b8b744276aa3f3c078509501200967d28cfc7b`.

This overlay replaces only the dense offline public pad used by
`H_2 = D^T A_2` and challenge encryption. The original dense implementation
remains the default and is selected by the `baseline` and `ypir-main` runtime
profiles.

## Parameters and arithmetic

- offline modulus: `q_v = 18014398492704769` (unchanged)
- supported experiment ring degrees: `2048` and `4096` (default `4096`)
- database rows: `32768`
- structured pad blocks: `16` at degree `2048`, `8` at degree `4096`
- rings: `Z_qv[X]/(X^2048+1)` or `Z_qv[X]/(X^4096+1)`
- structured pad version: `1`
- PRG domain: `small-client-pir/offline-pad/ypir-ntt/v1`
- arithmetic: exact Montgomery NTT under `q_v`; no modulus switching,
  rounding, or coefficient truncation
- security status: experimental Ring-LWE parameters, not audited

For each coefficient block `a`, the dense matrix represented by the module is

```text
NC(a)[i,j] =  a[j-i]          when j >= i
             -a[d+j-i] mod q  when j < i.
```

The module stacks `db_rows/d` such blocks vertically. For a database column,
each block contribution to `D^T A_2` is one negacyclic convolution and the
contributions are accumulated in NTT form. `A_2s` uses the transformed
polynomial `(a0,-a[d-1],...,-a1)`, preserving the original row-major pad
orientation.

## Runtime selection

```bash
# Offline optimization only, default d=4096.
native/scripts/build-run-paper-512mib.sh \
  --preproc-profile=distpir-offline

# Main and offline optimizations together, explicit d=2048.
native/scripts/build-run-paper-1gib.sh \
  --preproc-profile=hybrid --offline-ring-degree=2048
```

The four profiles are:

| profile | main hint | offline H2 |
| --- | --- | --- |
| `baseline` | dense LWE | dense LWE |
| `ypir-main` | exact NTT | dense LWE |
| `distpir-offline` | dense LWE | exact NTT |
| `hybrid` | exact NTT | exact NTT |

The paper scripts record both backends, ring degrees, block counts, versions,
moduli, domain labels, and security-status strings in every run directory.

## Validation

`//hintless_simplepir:offline_preprocessor_test` checks:

1. 64-bit NTT multiplication against naive `unsigned __int128` negacyclic
   arithmetic, including coefficients above 32 bits;
2. `A_2s` and `H_2` elementwise against a materialized dense pad;
3. structured challenge encryption and recovery through the original LHE;
4. deterministic pad derivation, dimension validation, and initialization of
   both production experiment degrees.

`MaterializePadForTesting()` exists only for these small differential tests;
the paper-size production path never calls it.
