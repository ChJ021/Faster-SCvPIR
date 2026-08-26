# 固定上游与许可

## Small-client vPIR 主上游

- 论文：Rathee, Lee, Popa, *Verifiable PIR with Small Client Storage*, IEEE S&P 2026，[ePrint 2025/1714](https://eprint.iacr.org/2025/1714)。
- 官方代码：[mayank0403/Verifiable-Hintless-PIR](https://github.com/mayank0403/Verifiable-Hintless-PIR)。
- 固定候选提交：`56b8b744276aa3f3c078509501200967d28cfc7b`（2025-09-26）。
- 状态：4 commits、无 tag/release/CI；学术 PoC，README 明示未经安全/正确性审计。
- 根许可：BSD 3-Clause。
- 组合许可：`verisimplepir/` 原始部分 MIT；`hintless_simplepir/`、`linpir/`、`lwe/` 原始部分 Apache-2.0；集成必须保留全部 notice 和文件头。
- 上游固定的更早基础：HintlessPIR `4be2ae8`、VeriSimplePIR `3643bb7`。

计划中的 vendoring 规则：

1. vendor 原文件不直接修改；
2. tarball、commit、SHA-256 和许可证一并固定；
3. 项目修改以 `native/patches/` 顺序 patch 管理；
4. 构建容器固定 Bazel、编译器和系统依赖；
5. 每次上游升级重新跑差分、安全负面和性能测试。

## 上游构建事实

主要依赖包括 Bazel、C++17、Abseil、protobuf、Tink C++、Google SHELL encryption、Eigen、Highway、OpenSSL 和 GSL。仓库没有固定 Bazel 版本，`MODULE.bazel` 为空；README 的依赖清单也少于 Dockerfile 与实际链接依赖。官方入口为：

```bash
bazel run -c opt --cxxopt='-std=c++17' \
  //hintless_simplepir:new_pir_test --cxxopt='-w' --copt='-w'
```

仓库只有一个完整 `cc_test`，没有独立 benchmark target、客户端/服务器 binary 或传输层。Dockerfile 固定 amd64，并保留 AES/SSE4 编译选项；当前源码默认测试约 2 MiB，而非 README 展示的 512 MiB，打印的 benchmark 也不含真实网络时间。第一阶段必须记录 CPU/编译特性并只做复现，不把结果标为 general-`H`。

## VIA 对照上游

- 论文：[VIA, ePrint 2025/2074](https://eprint.iacr.org/2025/2074)。
- 角色：Phase 7 比较后端，不进入 SC-vPIR-G1 安全证明。
- 固定提交、许可和可复现构建：待原生接入时补充；在此之前 benchmark 状态保持 `not-integrated`。
