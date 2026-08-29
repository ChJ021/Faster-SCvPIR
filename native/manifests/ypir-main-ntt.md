# YPIR main preprocessing overlay

Base upstream commit: `56b8b744276aa3f3c078509501200967d28cfc7b`.

This overlay adds a runtime-replaceable `MainPreprocessor` while retaining the
original dense-LWE backend as the default. The corresponding exact-NTT offline
`H_2` module is documented separately in `ypir-offline-ntt.md`.

## 512 MiB YPIR profile

- main modulus: `q0 = 4278255617` (unchanged)
- ring degree: `d = 2048`
- main secret dimension: `n = 2048`
- database columns: `16384`
- structured public-pad blocks: `8`
- ring: `Z_q0[X] / (X^2048 + 1)`
- PRG domain separation: `SHA-512(domain || 0x00 || public_seed)`, truncated to
  the selected PRNG seed length, with domain
  `small-client-pir/main-pad/ypir-ntt/v1`
- arithmetic: exact NTT; no modulus switch, rounding, or truncation
- security status: experimental Ring-LWE/ring-SIS parameterization, not audited

For a block polynomial `a`, the materialized matrix uses

```text
NC(a)[i,j] =  a[j-i]          when j >= i
             -a[d+j-i] mod q  when j < i.
```

Thus a row block multiplied by `NC(a)` is a negacyclic convolution. For
`NC(a) * s`, the implementation transforms `(a0, -a[d-1], ..., -a1)`. This
keeps `H = D*A`, `As = A*s`, and `ZA = Z*A` in the original layouts.

## One-command selection

```bash
native/scripts/build-run-paper-512mib.sh --preproc-profile=baseline
native/scripts/build-run-paper-512mib.sh --preproc-profile=ypir-main
native/scripts/build-run-paper-512mib.sh --preproc-profile=distpir-offline
native/scripts/build-run-paper-512mib.sh --preproc-profile=hybrid
```

The same binary handles both profiles. The script does not rewrite source or
compile-time macros based on the selected backend. It records the profile,
backend, ring degree, block count, version, modulus, domain label, and security
status under `native/logs/512mib/<profile>/<run-id>/`.

## Full-width public-pad sampling fix

The pinned upstream sampler previously constructed a 32-bit mask with
`Integer{1} << 32` and populated an Eigen row from a column vector without an
explicit transpose. The shift is undefined in C++, and under the recorded
optimized Clang build the combination produced an all-zero main public pad.
The overlay now:

- emits `~Integer{0}` when the requested sample width equals the integer width;
- assigns rows with `output.row(i) = buffer.transpose()`; and
- tests that both dense and YPIR main pads are nonzero and domain-separated.

Experiment logs captured before this fix are retained only as historical
timing/provenance records. They are not security-valid or post-fix performance
measurements.

## Files in the source overlay

```text
hintless_simplepir/main_preprocessor.{h,cc}
hintless_simplepir/main_preprocessor_test.cc
hintless_simplepir/offline_preprocessor.{h,cc}
hintless_simplepir/offline_preprocessor_test.cc
lwe/negacyclic_ntt.{h,cc}
lwe/sample_error.h
hintless_simplepir/{parameters,serialization,server,client,database_hwy}.*
hintless_simplepir/new_pir_test.cc
verisimplepir/src/lib/pir/preproc_pir.{h,cpp}
hintless_simplepir/BUILD
lwe/BUILD
```

No file under `native/cache`, `.venv`, or `.uv-cache` belongs to the overlay or
may be removed when installing it.
