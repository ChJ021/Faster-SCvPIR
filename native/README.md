# Small-client vPIR 上游 C++ PoC 部署

本目录把论文作者的 `Verifiable-Hintless-PIR` 原生实现固定为一个可重复执行的
**honest-H、2 MiB 正确性 smoke test**。它的用途是先复现作者代码，而不是声称已经完成
生产部署或 general-H 恶意安全扩展。

## 固定基线

| 项目 | 固定值 |
| --- | --- |
| 上游仓库 | `https://github.com/mayank0403/Verifiable-Hintless-PIR.git` |
| 上游提交 | `56b8b744276aa3f3c078509501200967d28cfc7b` |
| Bazel | `6.5.0`（项目内工具） |
| Bazel 模块系统 | 关闭：`--noenable_bzlmod` |
| 并行度 | `--jobs=2`，避免 8 GiB 级主机在 C++ 编译时耗尽内存 |
| 目标 | `//hintless_simplepir:new_pir_test` |
| 编译模式 | `-c opt`、C++17、Clang |

锁定值见 `manifests/upstream.lock.sh`，机器可读的部署边界见
`manifests/deployment.json`。脚本会拒绝错误的 origin、提交、Bazel 版本，以及不等于
已记录 Clang 18 兼容补丁的任何上游跟踪文件修改。

## 三个必须区分的状态

| 状态 | 数据库参数 | 当前是否启用 | 含义 |
| --- | --- | --- | --- |
| honest-H smoke | `2048 × 1024 × 8 bit = 2 MiB` | 是 | 固定提交中的默认端到端 GoogleTest；用于验证构建和协议正确性路径 |
| 论文 512 MiB profile | `32768 × 16384 × 8 bit = 512 MiB` | 由专用脚本原地启用 | 论文规模参数；以单独、可审查的参数和阶段 0 计时补丁启用，不能把 2 MiB 结果冒充论文复现 |
| general-H | 不适用 | 尚未实现 | 上游明确把“不依赖 honest hint 的 vPIR”列为范围外；本脚手架没有补上该安全能力 |

固定提交的上游 README 仍写着“默认值为 512 MiB”，但实际
`hintless_simplepir/new_pir_test.cc` 已把常量设为 `2048 × 1024`，即 2 MiB。
本部署以固定提交中的可执行代码为准，并把 512 MiB 仅记录为待启用的论文 profile。

上游 `WORKSPACE.bazel` 为 Eigen 3.4.0 固定的是 GitLab 过去生成的 ZIP 校验和；GitLab
现在为同一标签提交 `3147391d...` 生成了不同的 ZIP 容器，导致原始构建失败。为保持
上游 Git 工作树不变，本部署在项目内保存并校验该标签归档，通过 Bazel
`--override_repository` 使用 `native/vendor/eigen-3.4.0`。这是构建兼容层，不修改协议源码。

Clang 18 还会按 C++17 拒绝上游 `client.cc` 中五处从 `uint64_t` 到 `int64_t` 的列表
初始化收窄。`native/patches/clang18-row-index-type.patch` 只把这些行尾索引显式保持为
`int64_t`；预检固定校验补丁后文件的 SHA-256。该补丁不改变协议、密码参数或数据库布局。

运行时诊断还发现上游用有符号字面量 `1` 左移 31/63 位来构造无符号高斯误差中点，
这在 C++ 中是未定义行为，并被 Clang 18 编译成错误控制流。
`native/patches/clang18-unsigned-shift.patch` 将字面量改为 `Elem{1}`/`Elem64{1}`，保留
原本的中点与采样语义。预检同样固定校验补丁后的 `mat.cpp`。

当前 smoke 保持 `BSGS` 开启，保持 `FAKE_RUN` 与 `SH_RUN` 关闭。因此它走上游的
verifiable 路径且执行真实正确性检查，但安全声明仍受 honest-H 假设限制。

本项目现在明确采用该 honest-H 条件：`H = D A` 必须由可信发布者/可信预处理方生成，
或由其签名后再交给客户端。当前学术 PoC 假定该条件在协议外成立，并没有实现签名
生成、证书分发或验签代码；未通过可信渠道认证的 `H` 不属于本版本的安全声明。

## 环境边界

系统只安装 C/C++ 编译与链接所需的最小依赖（Clang、OpenSSL/GSL 开发头文件等）。
Bazel 可执行文件、Bazel 输出、依赖缓存、磁盘缓存和运行日志都保存在项目内：

```text
native/tools/                         Bazel 6.5.0 或 Bazelisk
native/toolchain/sources              固定校验和的第三方源归档
native/vendor/eigen-3.4.0             Eigen 本地 Bazel override
native/cache/bazel-user               Bazel output_user_root
native/cache/repository               外部仓库缓存
native/cache/disk                     编译动作缓存
native/cache/symlinks                 Bazel 便捷链接（不会写入 vendor）
native/logs/                           构建、测试与 /usr/bin/time 日志
```

脚本优先寻找 `native/tools/bazel-6.5.0`，其次寻找
`native/tools/bazel-6.5.0-linux-x86_64` 或 `native/tools/bazelisk`。也可以显式设置
`BAZEL_BIN`，但脚本仍会校验实际版本必须为 6.5.0。使用 Bazelisk 时固定设置
`USE_BAZEL_VERSION=6.5.0`。

当前工作区经常继承不可用的 `127.0.0.1:7897` HTTP(S) 代理，脚本默认在 Bazel
子进程中清除大小写两套 HTTP/HTTPS/ALL proxy 变量，避免外部依赖下载被错误代理阻断。
若所在网络确实依赖调用者提供的代理，可显式设置 `PIR_KEEP_PROXY=1`。

## 执行步骤

从项目根目录运行：

```bash
native/scripts/verify-upstream.sh
native/scripts/build.sh
native/scripts/list-tests.sh
native/scripts/run-smoke.sh
native/scripts/capture-environment.sh
```

- `verify-upstream.sh`：检查仓库 URL/提交/工作树、2 MiB 参数、模式开关、Clang 和 Bazel。
- `build.sh`：以固定选项编译目标并写入 `native/logs/build-*.log`。
- `list-tests.sh`：同时列出 Bazel 测试目标和 GoogleTest 测试用例。
- `run-smoke.sh`：运行端到端测试；标准输出、详细资源统计和退出状态分别写入
  `smoke-*.log`、`smoke-*.time.txt` 与 `smoke-*.metadata.txt`。
- `capture-environment.sh`：记录操作系统、CPU、内存、工具版本、包版本和 artifact
  SHA-256；不会转储环境变量或代理凭据。

所有 Bazel build/run 命令都显式携带 `--noenable_bzlmod` 和 `--jobs=2`。若必须在
不支持或不能稳定运行 Highway SIMD 的机器上，可按作者 README 的回退方式执行
`PIR_SCALAR=1 native/scripts/build.sh` 和 `PIR_SCALAR=1 native/scripts/run-smoke.sh`；脚本会
加入 `--cxxopt=-DHWY_COMPILE_ONLY_SCALAR=1` 并在日志中标明 `highway_mode=scalar`。
固定的 x86-64 基线不默认启用该退化路径。

## 结果解释边界

上游目标是单进程学术 PoC，客户端和服务端逻辑在同一个 GoogleTest 进程中运行，
没有真实网络传输。测试通过只证明该固定代码与参数在本机完成了端到端正确性路径；
它不等价于生产级服务、不验证网络协议，也不证明 general-H 恶意安全。论文 512 MiB
profile 应在 smoke 稳定后作为下一阶段单独启用，并保存独立的参数补丁与测量日志。

## 本机已验证结果

2026-08-24 的 native-dispatch 运行通过唯一测试
`HintlessSimplePir.EndToEndPIRTest`。二进制自身（不含 Bazel 分析）的 wall time 为
17.48 s，峰值 RSS 为 383564 KiB；上游内部计时报告总预处理 16.813 s、query-level
preprocessing 0.435342 s、online-only 0.00255128 s。机器可读记录与日志校验和见
`manifests/smoke-result-20260824.json`。

## 在原工作区切换到论文 512 MiB profile

`scripts/build-run-paper-512mib.sh` 是一个有意原地修改的服务器入口。它把固定的
`new_pir_test.cc` 从 `2048×1024, stack=1` 精确切换为
`32768×16384, stack=8`，随后复用项目内 Bazel 缓存构建并运行唯一端到端测试。
脚本固定校验作者 commit、两份 Clang 18 补丁和修改后源文件的 SHA-256；重复执行不会
再次修改源文件。它不会调用仍被保留为不可变 2 MiB 基线门禁的
`verify-upstream.sh`。

建议在 `tmux` 中执行：

```bash
native/scripts/build-run-paper-512mib.sh
```

也可以只准备参数或只构建：

```bash
native/scripts/build-run-paper-512mib.sh --prepare-only
native/scripts/build-run-paper-512mib.sh --build-only
```

执行记录保存在 `native/logs/512mib/<run-id>/`。脚本在有效内存低于 12 GiB 时默认
拒绝运行，并在低于建议的 16 GiB 时警告；`PIR_ALLOW_LOW_MEMORY=1` 仅用于明确接受
swap/OOM 风险的实验。该 profile 仍是作者的 honest-H 学术 PoC，并未获得 general-H
安全性。

### 阶段 0 细粒度计时

512 MiB 入口会确定性应用
`native/patches/stage0-preprocessing-timers.patch`。该补丁只增加计时输出，不改变算法、
密码参数、数据库布局、查询内容或验证等式。脚本校验补丁和应用后源文件的 SHA-256，
并要求上游工作树只包含两份 Clang 兼容补丁、512 MiB 参数和阶段 0 计时改动。

运行时，构建与测试输出通过 `tee` 同时显示在当前终端并记录到本次 run-id 目录；测试
进程通过 `stdbuf` 使用行缓冲，因而每条计时记录会在阶段完成后立即可见。统一格式为：

```text
[STAGE0_TIMING] scope=<scope> stage=<stage> duration_ms=<ms> duration_s=<s>
```

计时覆盖以下边界：

- 主 public parameters/稠密 A 展开、主 hint 矩阵乘；
- hint 模数编码、LinPIR database 创建和 BSGS 预处理；
- D/A/H 在 HintlessPIR 与 VeriSimplePIR 间的转换；
- 离线 A2 生成、H2 矩阵乘和挑战 C 加密；
- 每客户端 `D^T * ciphertexts` 及两侧格式转换；
- Z 恢复、压缩和 `ZA=CH` 检查；
- query prepare 的 `As`、LinPIR 请求、`Hs` 响应、恢复和验证；
- 在线查询生成、`D*u`、记录恢复和验证。

除完整的 `run.log` 外，脚本还会生成便于后续分析的：

```text
native/logs/512mib/<run-id>/stage0-timings.tsv
```

该 TSV 包含 `scope`、`stage`、`duration_ms` 和 `duration_s` 四列，并在测试结束后同步
打印到终端。`metadata.txt` 记录 TSV 路径和捕获到的计时条目数量；脚本会检查主 hint、
H2 和挑战加密等关键计时是否存在。`effective-stage0-source.patch`、源文件 SHA-256 和
计时补丁 SHA-256 也会保存在同一目录，方便复核实验使用的准确代码。
