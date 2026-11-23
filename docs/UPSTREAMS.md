# Upstream sources and licenses

The protocol implementation derives from Rathee, Lee and Popa's
[Verifiable PIR with Small Client Storage](https://eprint.iacr.org/2025/1714),
implemented in [Verifiable-Hintless-PIR](https://github.com/mayank0403/Verifiable-Hintless-PIR).

`manifests/upstream.lock.sh` pins commit
`56b8b744276aa3f3c078509501200967d28cfc7b` and Bazel 6.5.0. The patched source
tree is committed at the project root under `hintless_simplepir/`, `linpir/`,
`lwe/` and `verisimplepir/`; there is no separate patch file.
`scripts/prepare-dependencies.sh` only unpacks the pinned Eigen 3.4.0 archive
into `vendor/eigen-3.4.0`, which remains ignored by Git.

Native dependencies include C++17, Abseil, protobuf, Tink C++, Google SHELL
Encryption, Eigen, Highway, OpenSSL and GSL. Dependency definitions and license
notices are retained in the reconstructed upstream source. Structured hint
generation follows [YPIR](https://github.com/menonsamir/ypir).

License notices must be preserved:

- Upstream project: BSD 3-Clause.
- Original `verisimplepir/` components: MIT.
- Original `hintless_simplepir/`, `linpir/` and `lwe/` components: Apache-2.0.
