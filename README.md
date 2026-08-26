# Small-client vPIR 工程化第一版

本项目已从“VIA + 通用恶意编译器”的研究型组合，切换为 **Rathee–Lee–Popa 的 Small-client vPIR** 工程实例化。目标是降低密码学创新风险，优先得到可复现、可审计、可逐步替换为原生 C++ 密码后端的实现。

第一版现采用以下模型：单服务器、静态数据库、状态型客户端、恶意服务器、查询隐私与响应一致性、检测后中止，以及 **honest-H** 前提。`H = D A` 必须由可信发布者/可信预处理方生成并通过可信渠道交付，或由可信发布者签名背书。当前 PoC 把生成、分发和验签视为协议外前提；它不提供 freshness、rollback 防护或可用性保证。

因此第一版恢复论文实现使用的 honest-H 参数路线，并停止 general-H 原生改造。活动 SIS 界为

```text
beta_honest = B + ell * ||D||_infinity
```

这不等于已经完成生产安全证书；LWE、RLWE、SIS 参数和可信 `H` 来源仍需在部署时独立审计。

## 当前交付

- [`native/`](native/)：当前活动实现；作者 honest-H C++ PoC、512 MiB 配置、构建脚本与可信 `H` 边界。
- [`docs/VIA_COMPARISON.md`](docs/VIA_COMPARISON.md)：VIA 的后期对比方法与统一指标。
- [`small_client_vpir/`](small_client_vpir/) 与 [`tests/`](tests/)：此前构建的透明代数测试工具；保留用于回归等式和状态机，但不再定义活动参数或安全模型。
- [`comparators/via/`](comparators/via/)：VIA 比较适配器占位，不参与第一版安全主线。

Python 模型使用透明“FHE”，密文中直接含明文；它只验证算法维度、等式、状态转换和拒绝路径，**不提供 PIR 隐私、FHE 安全或生产级恶意安全**。当前活动实现以作者 C++/HintlessPIR/Google SHELL encryption 路径为准。

## 可选：使用 uv 运行代数回归测试

所有 Python 命令都通过 `uv` 创建的仓库内 `.venv` 执行：

```bash
make venv
make check
make demo
make benchmark
make benchmark-via
```

其中 `make benchmark` 只运行 `experimental-split-qlp-reference` 代数路径，用于检查分阶段指标字段；它不是 Figure 5 合并安全基线，也不能用于安全或性能结论。`make demo` 才演示 `figure5-combined` 控制流。

等价的直接命令：

```bash
uv --cache-dir .uv-cache --offline venv --allow-existing --python 3.12 .venv
uv --cache-dir .uv-cache --offline run --python .venv/bin/python python -m unittest discover -s tests -v
uv --cache-dir .uv-cache --offline run --python .venv/bin/python python -m small_client_vpir demo
uv --cache-dir .uv-cache --offline run --python .venv/bin/python python -m small_client_vpir benchmark --protocol small-client
```

## 原生作者 PoC 复现

作者的 C++ honest-H 基线已经完成 512 MiB 端到端运行，并在回退 general-H 后重新
编译成功。工具、Bazel
输出、第三方源码缓存与日志都放在 `native/`；只有 Clang、OpenSSL/GSL 开发库和 GDB
等基础系统包由 apt 安装。复现入口为：

```bash
make native-verify
make native-build
make native-list-tests
make native-smoke
make native-env
```

成功结果及其 SHA-256 见
[`native/manifests/smoke-result-20260824.json`](native/manifests/smoke-result-20260824.json)，
具体构建边界见 [`native/README.md`](native/README.md)。该结果仍是论文作者的 honest-H、
单进程学术 PoC；不是 general-H 或网络服务。

## 为什么第一版不用 VIA 或 Verifiable BALANCED-PIR

- Small-client vPIR 已有专用 vLHE/vPIR 定理、作者 C++ PoC、证明压缩和查询级预处理；采用 honest-H 后可直接复用作者已实现的 32 位参数路径，密码学创新风险最低。
- VIA 本身只证明半诚实查询隐私与诚实正确性。要达到同一恶意模型，还需新的通用编译层、LDC、proximity test、承诺和 keyword-PIR 适配，组合与常数风险更高。
- Verifiable BALANCED-PIR 已直接提供可验证 stateful PIR，但周期性全库离线阶段、失败后的时序处理和小记录布局更强地限制部署；它不是当前“先复用现成 C++ 密码路径”的最低风险选项。

VIA 仍被保留为第二阶段性能对照。只有在两个原生实现使用同一机器、数据库布局、记录大小、安全等级和统计口径时，才比较哪一个更优。

## 主要依据

- Rathee, Lee, Popa, *Verifiable PIR with Small Client Storage*, IEEE S&P 2026 / [IACR ePrint 2025/1714](https://eprint.iacr.org/2025/1714)。
- 作者实现：[Verifiable-Hintless-PIR](https://github.com/mayank0403/Verifiable-Hintless-PIR)，本项目计划固定提交 `56b8b744276aa3f3c078509501200967d28cfc7b`。
- VIA：[IACR ePrint 2025/2074](https://eprint.iacr.org/2025/2074)，仅作为后期对照。

本地研究 PDF 和用户原始课题材料被保留为证据输入；LaTeX 主稿、旧 MVIA 原型和论文专用脚本已从工程入口移除。
