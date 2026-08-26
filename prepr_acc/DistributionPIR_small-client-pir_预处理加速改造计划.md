# small-client-pir 借鉴 Distributional PIR 的预处理加速改造计划

> 文档状态：阶段 0 已于 2026-08-26 完成；阶段 1～6 仍为设计计划。阶段 0 仅增加计时与实验记录，不包含预处理加速、参数调整或协议修改。基线结果见 [阶段0_512MiB预处理性能基线.md](阶段0_512MiB预处理性能基线.md)。

## 1. 改造目标

从 *Distributional Private Information Retrieval* 第六章中，只借鉴适合 small-client-pir 的预处理加速方法：

- 用 RingLWE/negacyclic 结构代替稠密随机矩阵；
- 用 NTT 加速服务器 hint 计算；
- 用多项式乘法加速客户端 \(As\) 和挑战密文生成；
- 加速后仍将结果转换为现有的普通 LWE 向量或矩阵；
- 保留当前 SimplePIR 在线数据库扫描、LinPIR/BSGS 和验证框架。

本计划明确不做：

- 不把默认主 LWE 模数改成 \(2^{32}\)；
- 不完整复现 Distributional PIR；
- 不引入分布感知 PIR 外层协议；
- 不改造 GPU 在线计算路径；
- 第一版不引入 \(q_1\rightarrow q_0\) 近似 modulus switching；
- 不允许破坏 \(ZA=CH\) 等精确验证关系。

## 2. 总体技术决策

### 2.1 保留现有模数

主 LWE 模数继续使用：

\[
q_0=4278255617.
\]

离线验证 LWE 模数继续使用：

\[
q_v=18014398492704769.
\]

两者都是 NTT-friendly 素数，因此可以直接在原模数上完成 RingLWE 多项式乘法。第一版将 Distributional PIR 的模数切换视为退化情形：

\[
q_1=q_2,
\]

即暂时不做 modulus switching，只采用其结构化预处理和 RingLWE 快速乘法思想。

### 2.2 保持精确线性关系

主路径必须始终满足：

\[
H=DA\pmod {q_0},
\]

\[
As=A s\pmod {q_0}.
\]

第一版禁止采用以下方式生成主 hint：

\[
H=\operatorname{MS}_{q_1\rightarrow q_0}(DA_1),
\qquad
A=\operatorname{MS}_{q_1\rightarrow q_0}(A_1),
\]

因为逐元素舍入通常会导致：

\[
\operatorname{MS}(DA_1)\ne D\operatorname{MS}(A_1),
\]

从而破坏当前验证所要求的精确矩阵等式。

### 2.3 分成两条改造路线

建议先改造离线验证 LWE，再改造主 LWE：

| 路线 | 改造对象 | 优先级 | 原因 |
| --- | --- | ---: | --- |
| A | \(A_2,H_2\) 和挑战 \(C\) 的加密 | 第一阶段 | 预计计算量大，且不改变主 \(A/H\) 验证 hash，协议风险较低 |
| B | 主 \(A,H,As\) | 第二阶段 | 能继续加速全局 hint 和 query prepare，但涉及 RingLWE 查询安全及结构化验证 hash 的安全性 |

## 3. 目标数学结构

### 3.1 结构化公共矩阵

设环维数为 \(d\)，将公共矩阵表示为多个 negacyclic 块：

\[
A=
\begin{bmatrix}
\operatorname{NC}(a_0)\\
\operatorname{NC}(a_1)\\
\vdots\\
\operatorname{NC}(a_{b-1})
\end{bmatrix},
\qquad
a_i\in\mathbb Z_q[X]/(X^d+1).
\]

其中：

\[
b=\left\lceil \frac{m}{d}\right\rceil.
\]

对于当前 512 MiB 配置：

\[
m=\texttt{db\_cols}=16384.
\]

若选择 \(d=2048\)，则：

\[
b=8,
\]

数据库列可以被完整分块，不需要处理尾块。

### 3.2 客户端计算

当前客户端计算稠密矩阵向量乘：

\[
As=A s.
\]

改造后按块执行多项式乘法：

\[
(As)_i=a_i(X)s(X)\pmod{X^d+1,q}.
\]

最后将每个结果多项式的系数串联为现有长度为 `db_cols` 的 LWE 向量。服务器看到的在线查询格式保持不变。

### 3.3 服务器主 hint

将数据库按列分块：

\[
D=[D_0\mid D_1\mid\cdots\mid D_{b-1}],
\]

然后计算：

\[
H=\sum_{i=0}^{b-1}D_i\operatorname{NC}(a_i).
\]

每个数据库行块与 \(a_i\) 的乘法使用 NTT。最终输出仍为普通矩阵：

\[
H\in\mathbb Z_{q_0}^{\texttt{db\_rows}\times d},
\]

并继续交给现有 LinPIR/BSGS 处理。

### 3.4 离线验证 hint

将离线公共矩阵 \(A_2\) 改成结构化矩阵：

\[
A_2=
\begin{bmatrix}
\operatorname{NC}(a_{2,0})\\
\vdots\\
\operatorname{NC}(a_{2,b_2-1})
\end{bmatrix},
\]

并在原 54 位素数模数下精确计算：

\[
H_2=D^TA_2\pmod {q_v}.
\]

挑战 \(C\) 的每一行使用：

\[
c_i=A_2s_i+e_i+\Delta_v C_i.
\]

服务器仍按现有方式计算：

\[
D^Tc_i.
\]

因此每客户端的数据库扫描和 Z 恢复接口原则上不需要改变。

## 4. 分阶段实施计划

### 阶段 0：建立细粒度性能基线

目的：确定当前约 642.5 秒全局预处理的真实组成，避免优化错误目标。

完成状态：已完成。运行脚本会实时显示计时行并同步写入 `run.log`，结束后再生成
`stage0-timings.tsv`。本阶段没有更改算法、模数、数据库布局或验证关系。

已增加以下独立计时项：

1. 主公共矩阵生成或展开；
2. 主 \(H=DA\)；
3. hint 格式转换；
4. LinPIR database 创建；
5. LinPIR BSGS 预处理；
6. \(A_2\) 生成；
7. \(H_2=D^TA_2\)；
8. 128 个挑战密文生成；
9. 每客户端 \(D^Tc_i\)；
10. Z 恢复、压缩和验证；
11. 客户端主 \(As\)；
12. LinPIR prepare 请求和响应。

阶段输出：

- 512 MiB 分阶段耗时表；
- CPU 时间与墙钟时间；
- 峰值内存；
- 各阶段占总预处理时间的比例。

上述输出已由 run-id `20260826T065414Z-844069` 完成，详细数据和结论见
[阶段0_512MiB预处理性能基线.md](阶段0_512MiB预处理性能基线.md)。

### 阶段 1：数学、参数和安全设计

#### 1.1 主路径候选参数

建议初始候选：

\[
d_{\mathrm{main}}=2048,
\qquad
q_0=4278255617.
\]

选择理由：

- `db_cols=16384` 可以整除 2048；
- 当前 \(q_0\) 支持 2048 维 negacyclic NTT；
- 当前 LinPIR 环维数为 4096，可以容纳 2048 维秘密向量；
- 与 Distributional PIR 的 32 位参数规模一致。

正式采用前必须完成：

- RingLWE 安全估计；
- 误差分布检查；
- 查询解密失败概率分析；
- 结构化 \(A\) 对验证 hash 的影响分析；
- LinPIR 在秘密维数由 1408 增至 2048 后的正确性和性能评估。

#### 1.2 离线路径候选参数

当前 `offline_lwe_secret_dim=2816` 不是标准二次幂环维数。候选参数为：

- \(d_{\mathrm{offline}}=2048\)：内存较小，但必须确认 54 位模数下的安全性；
- \(d_{\mathrm{offline}}=4096\)：安全余量可能更大，但 \(H_2\) 和客户端状态会增大。

不能仅为了方便实现而直接选择 4096，必须先使用安全估计器评估。

#### 1.3 安全证明检查

主结构化矩阵会引入两项安全假设变化：

- 查询隐私从普通 LWE 转为 RingLWE；
- \(H=DA\) 作为验证 hash 时，碰撞安全可能从 SIS 转为 ring-SIS/ideal-SIS。

第二项是路线 B 的安全门槛。如果无法获得可接受的 ring-SIS 参数或论证，则停止主 \(A/H\) 结构化改造，只保留离线 \(A_2/H_2\) 加速路线。

### 阶段 2：实现独立的结构化矩阵模块

实施时计划增加独立组件，例如：

```text
lwe/structured_lwe_pad.h
lwe/structured_lwe_pad.cc
lwe/negacyclic_ntt.h
lwe/negacyclic_ntt.cc
```

核心对象建议为：

```text
StructuredLwePad
  modulus
  log_ring_degree
  ring_degree
  block_count
  seed
  coefficient_polynomials
  ntt_polynomials
```

模块需要提供：

- 从种子确定性生成多项式；
- 系数形式与 NTT 形式转换；
- 计算 \(As\)；
- 计算 \(DA\)；
- 计算 \(D^TA\)；
- 仅供测试使用的稠密矩阵展开；
- 明确并固定 first-row、first-column、系数反转和符号约定；
- NTT scratch buffer 的复用接口。

服务器和客户端只共享种子与参数，不发送完整矩阵 \(A\)。

### 阶段 3：优先改造离线 \(A_2/H_2\)

这是第一条实际集成路线，涉及：

- `verisimplepir/src/lib/pir/lhe.{h,cpp}`；
- `verisimplepir/src/lib/pir/preproc_pir.{h,cpp}`；
- `hintless_simplepir/new_pir_test.cc`；
- `hintless_simplepir/database_hwy.{h,cc}`。

计划修改：

1. `PreprocInitNew64()` 不再返回稠密 `Matrix64 A_2`，改为返回结构化 pad；
2. `PreprocClientMessageNew64()` 使用多项式 NTT 计算每个 \(A_2s_i\)；
3. 增加 `TransposeProductStructured64()`，直接计算 \(D^TA_2\)；
4. 最终仍输出当前格式的 `H_2_vec`，使 Z 恢复逻辑保持不变；
5. `TransposeProductCiphertexts64()` 保持不变；
6. Z 恢复、压缩和最终验证保持不变；
7. 保留原稠密 backend，供差分测试和回退使用。

本阶段不修改：

- 主 \(A/H\)；
- 主 LWE 模数；
- LinPIR；
- 在线查询格式；
- \(ZA=CH\) 主验证关系。

### 阶段 4：改造主 \(A/H/As\)

只有在阶段 1 的安全检查通过后才进入本阶段。

#### 4.1 服务端 public pad

当前服务器会从 PRNG seed 展开完整稠密矩阵。计划改为：

- 保留现有 PRNG seed 字段；
- 根据 seed 生成 8 个 2048 维多项式；
- `Server` 保存 `StructuredLwePad`，不保存完整 Eigen 矩阵；
- 增加 dense/structured 两种 preprocessing backend；
- 为不同用途的 pad 使用独立的 PRNG 域分离标签。

#### 4.2 服务端主 hint

计划新增：

```text
UpdateHintsStructuredNtt()
```

该函数负责：

1. 按 2048 列对数据库分块；
2. 将数据库行块解释为环元素；
3. 使用预计算的 pad NTT 形式执行乘法；
4. 对各块求和并逆 NTT；
5. 输出与当前 `Hints()` 完全相同的数据类型和布局。

LinPIR 接收到的仍然是普通 hint 矩阵，不需要感知结构化 pad。

#### 4.3 客户端 \(As\)

计划：

- 从 public seed 重建与服务器相同的多项式；
- 将主秘密维数调整为经验证的环维数；
- 使用 NTT 计算各个 \(a_i s\)；
- 拼接为长度 `db_cols` 的 `As`；
- 查询继续使用：

\[
u=As+e+\Delta e_j\pmod {q_0}.
\]

查询序列化格式保持不变。

#### 4.4 主验证适配

计划增加：

```text
MultiplyRightStructured()
VerifyPreprocZCompressedStructured()
```

用于直接计算：

\[
RZ\cdot A,
\]

而不在客户端展开完整矩阵。由于 \(H=DA\) 在同一个 \(q_0\) 下精确计算，以下等式仍应逐元素精确成立：

\[
ZA=CH,
\]

\[
(RZ)(As)=(RC)(Hs).
\]

### 阶段 5：参数、协议和兼容性整理

计划在 `hintless_simplepir/parameters.h` 中增加：

```text
preprocessing_backend
main_ring_log_n
offline_ring_log_n
structured_pad_version
main_pad_block_count
offline_pad_block_count
```

建议使用运行时枚举：

```text
DENSE_LWE
STRUCTURED_NTT
```

而不是继续增加全局编译宏。

计划在 `hintless_simplepir/serialization.proto` 的 public parameters 中增加：

- pad 算法版本；
- 环维数；
- 块数；
- 模数标识；
- PRNG 域分离标签；
- preprocessing backend 标识。

在线 `ct_query_vector` 的格式原则上不变。

### 阶段 6：性能优化和并行化

只有在正确性、验证和安全检查通过后才进行：

- 多个数据库行批量 NTT；
- 预计算并缓存 pad 的 NTT 形式；
- 按数据库行、block 或 shard 并行；
- 避免完整数据库的 NTT 形式长期驻留内存；
- 复用 NTT scratch buffer；
- 针对 32 位模数使用 64/128 位中间结果；
- 针对 54 位模数使用 `__int128`、Montgomery 或现有 RNS 实现；
- 控制 NUMA 和内存带宽；
- 避免主 \(A\) 和 \(A_2\) 的重复生成或重复转换。

不建议将完整数据库长期保存为 NTT 形式，因为这会增加内存表示，且可能降低在线阶段的内存带宽效率。

## 5. 预计代码影响范围

| 文件或模块 | 计划影响 |
| --- | --- |
| `lwe/lwe_symmetric_encryption.h` | 抽离稠密 pad 与结构化 pad；保留旧接口用于对照 |
| `lwe/structured_lwe_pad.{h,cc}` | 新增结构化 pad 生成和表示 |
| `lwe/negacyclic_ntt.{h,cc}` | 新增 NTT 乘法内核 |
| `hintless_simplepir/parameters.h` | 新增 backend 和环参数 |
| `hintless_simplepir/server.{h,cc}` | 生成并保存结构化 public pad |
| `hintless_simplepir/database_hwy.{h,cc}` | 新增主 hint 和离线 hint 的 NTT kernel |
| `hintless_simplepir/client.{h,cc}` | NTT 计算 \(As\)，避免展开完整稠密 \(A\) |
| `hintless_simplepir/serialization.proto` | 增加公共参数版本和环参数 |
| `verisimplepir/src/lib/pir/lhe.{h,cpp}` | 结构化 \(A_2\) 和挑战加密 |
| `verisimplepir/src/lib/pir/preproc_pir.{h,cpp}` | 结构化预处理和验证乘法 |
| `hintless_simplepir/new_pir_test.cc` | backend 切换、细粒度计时和差分测试 |
| 各 `BUILD` 文件 | 增加结构化 NTT 模块依赖 |
| LinPIR 核心 | 原则上不修改 |
| 在线 `InnerProductWith()` | 不修改 |

## 6. 正确性测试计划

### 6.1 模块级差分测试

对较小环维数和固定 seed：

1. 将结构化 \(A\) 展开为测试用稠密矩阵；
2. 比较 NTT 与稠密 \(As\)：

   \[
   A_{\mathrm{NTT}}s=A_{\mathrm{dense}}s;
   \]

3. 比较主 hint：

   \[
   DA_{\mathrm{NTT}}=DA_{\mathrm{dense}};
   \]

4. 比较离线 hint：

   \[
   D^TA_{2,\mathrm{NTT}}=D^TA_{2,\mathrm{dense}}.
   \]

所有比较要求逐元素完全一致，不接受浮点误差或近似相等。

### 6.2 协议等式测试

每次集成都检查：

\[
H=DA,
\]

\[
ZA=CH,
\]

\[
(RZ)(As)=(RC)(Hs),
\]

\[
(RZ)u=(RC)v.
\]

### 6.3 端到端测试层级

依次运行：

1. 极小确定性数据库；
2. 当前 smoke 数据库；
3. 2 MiB；
4. 32 MiB 或 64 MiB；
5. 512 MiB。

每一级都需要验证：

- 查询恢复记录正确；
- 所有证明检查通过；
- dense 与 structured 查询相同索引时恢复结果一致；
- 多个边界索引和随机索引均通过；
- stacking 不跨列；
- 多次运行的结构化 public pad 可由相同 seed 确定性重建。

## 7. 性能评估计划

### 7.1 同参数内核比较

在相同环维数下比较：

- dense \(d=2048\)；
- structured NTT \(d=2048\)。

这一组数据用于测量算法本身的加速，而不混入安全参数变化。

### 7.2 旧系统端到端比较

比较：

- 当前 \(n=1408/2816\)；
- 新参数和 structured NTT。

这一组数据用于评估用户实际获得的端到端收益。

### 7.3 建议验收指标

- 主 `Compute_A_times_s` 至少加速 5～10 倍；
- 主 hint kernel 至少加速 5 倍；
- \(A_2/H_2\) kernel 获得显著加速；
- 在线 \(Du\) 延迟下降或基本不变，允许波动不超过 5%；
- query/response 大小不增加；
- prepare 通信量不显著增加；
- 峰值内存不超过基线的 1.2 倍；
- 所有验证逐元素精确通过。

最终约 724 秒的总预处理可以降低多少，应在阶段 0 得到细分数据后再制定目标，不能直接套用 Distributional PIR 论文中的加速倍数。

## 8. 参数和内存影响预估

当前 512 MiB 配置中，主要 hint 大小约为：

- 主 \(H\)：\(32768\times1408\times4=176\) MiB；
- 离线 \(H_2\)：\(16384\times2816\times8=352\) MiB；
- 合计：约 528 MiB。

如果只把主维数改成 2048：

- 主 \(H\) 增至 256 MiB；
- \(H_2\) 保持 352 MiB；
- 总 hint 约 608 MiB。

如果只把离线维数改成 4096：

- 主 \(H\) 保持 176 MiB；
- \(H_2\) 增至 512 MiB；
- 总 hint 约 688 MiB。

如果主维数和离线维数分别改成 2048 和 4096：

- 总 hint 约 768 MiB。

因此，环维数选择必须同时考虑安全、预处理时间、LinPIR 成本和峰值内存。

## 9. 主要风险及处理

| 风险 | 等级 | 处理计划 |
| --- | ---: | --- |
| 结构化主 \(A\) 改变 SIS hash 安全假设 | 高 | 主路径实施前完成 ring-SIS 分析；不通过则停止路线 B |
| 1408/2816 改为二次幂影响安全和内存 | 高 | 使用 LWE/RingLWE estimator 分别评估 2048 和 4096 |
| negacyclic 行列方向、反转或符号错误 | 高 | 使用固定小矩阵进行逐元素差分测试 |
| 54 位 NTT 中间结果溢出 | 高 | 使用 `__int128` 或 Montgomery，并加入最大值测试 |
| LinPIR 因秘密维数变化而变慢 | 中 | 单独测量 BSGS、旋转和 database 创建成本 |
| hint 增大 | 中 | 参数选择时同时评估时间和内存 |
| NTT 加速后 LinPIR 成为新瓶颈 | 中 | 阶段 0 和阶段 6 分别计时，不提前扩大改造范围 |
| seed 或 PRNG 展开顺序不一致 | 中 | 增加版本和域分离；测试服务器与客户端的 pad 哈希 |
| 直接套用 modulus switching 破坏验证 | 高 | 第一版禁止近似 hint，始终精确计算 \(H=DA\) |

## 10. Go/No-Go 决策点

### 10.1 离线 \(A_2/H_2\) 决策点

只有满足以下条件才进入集成：

- 找到安全的二次幂环维数；
- 54 位 NTT 不发生溢出；
- 挑战解密失败概率不劣于当前参数；
- \(H_2\) 内存增长可以接受；
- 小规模 NTT 与稠密实现逐元素一致。

### 10.2 主 \(A/H\) 决策点

只有满足以下条件才实施：

- RingLWE 查询参数达到目标安全级别；
- ring-SIS/结构化 hash 安全性可以接受；
- 主 hint 增大后的内存可以接受；
- LinPIR 能正确处理新的秘密维数；
- 小规模差分测试逐元素一致；
- 结构化验证乘法能够精确通过全部等式。

### 10.3 Modulus switching 决策点

默认结论为“不实施”。只有出现以下需求时再单独立项：

- 当前素数模运算被证明是在线主要瓶颈；
- 确实需要切换到 \(2^{32}\)；
- 可以接受 LinPIR、CRT 和验证体系的进一步重构；
- 已完成舍入噪声和验证正确性的独立分析。

## 11. 推荐落地顺序

1. 细分当前 512 MiB 预处理耗时；
2. 完成 54 位离线 RingLWE 参数评估；
3. 实现通用结构化 pad 和 NTT 差分测试；
4. 先加速 \(A_2/H_2\) 与挑战加密；
5. 在不改变主 \(A/H\) 的情况下运行完整 512 MiB 对比；
6. 完成主结构化 \(A\) 的 RingLWE/ring-SIS 安全评估；
7. 再加速主 \(H=DA\) 和客户端 \(As\)；
8. 保留原 \(q_0\)，不进行 modulus switching；
9. 完成端到端正确性、验证、性能和内存报告；
10. 结构化路径稳定后，再决定是否将其设为默认 backend。

## 12. 最终原则

本计划的核心原则是：

> 借鉴 Distributional PIR 的 RingLWE 结构和 NTT 预处理，但保留 small-client-pir 的模数体系、LWE 在线格式和精确验证关系。

第一阶段优先改造与主验证 hash 解耦的 \(A_2/H_2\) 路径；第二阶段只有在 RingLWE 和 ring-SIS 安全分析通过后，才改造主 \(A/H/As\) 路径。整个过程中始终保留稠密实现作为正确性参照和回退方案。
