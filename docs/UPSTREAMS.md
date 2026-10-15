# Upstream sources and licenses

The native base is Rathee, Lee and Popa's
[Verifiable PIR with Small Client Storage](https://eprint.iacr.org/2025/1714),
implemented in [Verifiable-Hintless-PIR](https://github.com/mayank0403/Verifiable-Hintless-PIR).

`native/manifests/upstream.lock.sh` pins commit
`56b8b744276aa3f3c078509501200967d28cfc7b`, Bazel 6.5.0 and the project patch
checksum. `native/scripts/prepare-upstream.sh` checks out that commit, applies
`native/patches/ypir-ntt-preprocessing.patch`, and unpacks the pinned Eigen 3.4.0
archive. Generated source resides under `native/vendor/` and is ignored by Git.
`make native-verify` checks the prepared source and toolchain.

Native dependencies include C++17, Abseil, protobuf, Tink C++, Google SHELL
Encryption, Eigen, Highway, OpenSSL and GSL. Dependency definitions and license
notices are retained in the reconstructed upstream source. Structured hint
generation follows [YPIR](https://github.com/menonsamir/ypir).

License notices must be preserved:

- Upstream project: BSD 3-Clause.
- Original `verisimplepir/` components: MIT.
- Original `hintless_simplepir/`, `linpir/` and `lwe/` components: Apache-2.0.

The security estimators are pinned separately in
`native/security/estimator.lock.sh`; see [the security model](../native/security/README.md).
