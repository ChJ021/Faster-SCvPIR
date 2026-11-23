# 方向 1 改造指导：服务器辅助 / 低维 hint 的离线解密

- 状态：implementation guide（供后续改造使用，不是论文正文）
- 目标项目：`~/Faster-SCvPIR`
- 关联方向：`docs/plans/direction-3-incremental-verified-preprocessing.md`
- 实测基线：128 MiB / `negacyclic-both`，总计 43.07 s，其中客户端 `offline_recover_Z` 28.61 s

---

## 0. 目标、非目标与前置条件

### 目标

降低客户端离线预处理成本，重点是：

1. 客户端不再做 40 次 `H2 × sk_i` 稠密矩阵向量乘；
2. 降低或消除客户端临时持有的 `H2`（128 MiB 约 352 MiB，4 GiB 约 1.47 GiB）；
3. 保持 `Z = C·D`、`Z' = RZ`、`C' = RC` 和三个验证等式不变；
4. 不改变在线查询路径与主 hint `H` 的语义。

### 非目标

- 不改变查询隐私、在线响应格式和 `H·s` 的 FHE 委托方式；
- 不在本方向处理数据库更新（见方向 3）；
- 不追求“无条件消除所有 hint”：如果只采用轻量 LHE，客户端仍需一个**降维后的 mask hint**；
- 不修改安全模型中的诚实 hint 假设。

### 前置条件

- 已能运行 `make paper-run SIZE=128mib PROFILE=negacyclic-both`；
- 建议先从旧仓库恢复以下内容用于测试和参数分析：
  - `~/Faster-SCvPIR-rewritten/native/security/`（LWE 参数估计）；
  - 旧仓库的单元测试可作为参考，但本方向需要新增针对 mask 的测试。
- 当前精简项目没有 `tests/`；实现本方向时必须新增至少一组 mask 正确性测试。

---

## 1. 实测基线与瓶颈

来自 128 MiB / `negacyclic-both` 的一次运行：

| 阶段 | 时间 | 备注 |
|---|---:|---|
| 总预处理 | 43.07 s | |
| 客户端 `offline_recover_Z` | 28.61 s | 40 次 `H2 × sk_i` |
| 服务器全局预处理 | 10.93 s | |
| 其中 main hint `H` | 3.05 s | 结构化 NTT |
| 其中 offline `H2` | 4.68 s | 结构化 NTT |
| 服务器 per-client `D^T C^T` | 1.18 s | |
| 客户端 challenge 加密 | 1.83 s | |
| Prepare + Online | 0.17 s | |
| `Hints` 总量 | 576 MiB | `H2` 约 352 MiB |
| 客户端长期状态 `RZ` | 128 KiB | |
| 进程峰值 RSS | 约 1.87 GiB | |

结论：服务器端的结构化 NTT 已经比较充分；**客户端 `H2` 解密是第一位瓶颈**。

---

## 2. 当前代码路径（精确到函数）

### 2.1 实验驱动

`hintless_simplepir/pir_experiment.cc`：

| 行号范围（约） | 作用 |
|---|---|
| 318–345 | 生成 `A_2`：结构化走 `YpirOfflinePreprocessor::Create`，dense 走 `pir.PreprocInitNew64()` |
| 347–384 | 计算 `H_2 = D^T A_2` 并转换成行形式 |
| 386–405 | 客户端加密挑战 `C`（`offline_preprocessor->EncryptChallenges` 或 `pir.PreprocClientMessageNew64`） |
| 407–433 | 服务器计算 `D^T C^T`（`server->TransposeProductCiphertexts64`） |
| 435–446 | **客户端 `PreprocRecoverZNew64` 解密 Z** |
| 448–468 | 采样 `R`，计算 `RC = C'`、`RZ = Z'` |
| 470–484 | `client->MultiplyRightByMainPad` + `VerifyPreprocZCompressedGivenLeftProduct` |

### 2.2 PIR 预处理核心

`verisimplepir/src/lib/pir/preproc_pir.cpp`：

- `PreprocClientMessageNew64(A, C)`：
  - 为 `C` 的每一行采样一个独立 `sk_i`；
  - 用 `lhe.encrypt64(A, sk_i, C_i, true)` 加密。
- `PreprocRecoverZNew64(H_2, sks, res_ct, blowup)`：
  - 对 `row_ind = 0..stat_sec_param-1` 循环；
  - 调用 `lhe.decrypt_preproc64(H_2, sks[row_ind], res_ct[row_ind], blowup, true)`。
- `stat_sec_param = STAT_SEC_PARAM = 40`，`LOG_Q = 31`，压缩行数 `rlc_count = ceil(40/31) = 2`。

`verisimplepir/src/lib/pir/lhe.cpp`：

- `decrypt_preproc64(H, sk, ct, blowup, preproc)`：
  ```cpp
  Matrix64 H_sk = matMulVec64(H, sk);
  Matrix64 scaled_pt = matSub64(ct, H_sk);
  Matrix pt = matDivScalar64(scaled_pt, Delta64_preproc);
  ```
  其中 `H = H2`，`matMulVec64` 是 `m × n_off` 稠密矩阵乘向量，是 28.6 s 的直接来源。

### 2.3 结构化离线 pad

`hintless_simplepir/offline_preprocessor.h`：

- `YpirOfflinePreprocessor::ComputePadTimesSecret(const Matrix64& secret)`：
  - 计算 `A_2 · secret`，返回 `db_rows × 1`；
  - 内部使用结构化 NTT，成本远低于 `H2 × secret`。
- `EncryptChallenges(const LHE&, const BinaryMatrix&)`：
  - 用结构化 `A_2` 加密挑战。

这个接口是方向 1 的关键：客户端可以复用它计算 `pre_i = A2 · sk_i`。

### 2.4 服务器全局与每客户端

`hintless_simplepir/server.cc`：

- `PreprocessBSGS()`：
  - `main_preprocessor_->ComputeHint(*database_)` 计算 `H`；
  - `database_->SetHints(...)`；
  - 对每个 shard/modulus：`EncodeLweMatrix(hint, ...)`、`LinPirDatabase::CreateBSGS`、`LinPirServer::CreateBSGS`、`PreprocessBSGS`。
- `TransposeProductCiphertexts64(...)`：对 40 个挑战密文做 `D^T`，返回每客户端响应。

注意：`H2` 是在实验驱动里计算的，不在 `PreprocessBSGS` 里；因此移除 `H2` 需要同时改实验驱动和客户端解密路径。

---

## 3. 关键问题：为什么“直接把 `H2·sk` 搬到服务器”不够

一个自然的想法是：

```text
客户端加密 A2·sk_i  ->  服务器算 D^T·Enc(A2 sk_i)  ->  客户端解密 mask
```

但这里有一个必须正面处理的 **pad 问题**：

1. 客户端用某个 mask pad `A_mask` 和密钥 `sk_mask` 加密 `pre_i = A2 sk_i`：
   ```text
   c_i = A_mask · sk_mask + e_i + Δ_mask · pre_i
   ```
2. 服务器应用 `D^T`：
   ```text
   D^T c_i = (D^T A_mask) · sk_mask + D^T e_i + Δ_mask · D^T pre_i
            = H_mask · sk_mask + ... + Δ_mask · H2 sk_i
   ```
3. 客户端要解密 `D^T c_i`，必须知道
   ```text
   H_mask = D^T · A_mask
   ```
   否则无法消掉 `H_mask · sk_mask`。

因此：

- 如果 `A_mask = A2`，则 `H_mask = H2`，客户端又需要 `H2`，没有收益；
- 如果 `A_mask` 任意，客户端需要一个**新的 mask hint `H_mask`**；
- 要真正“无 hint”，必须使用**全同态/可用于任意线性映射的解密结构**（例如 BFV/LinPIR），而不是只靠一个 LHE pad。

由此得到三条可行路线：

| 路线 | 客户端持有 | 是否消除 H2 | 主要代价 |
|---|---|---|---|
| C：批量/流式优化 | 仍是 H2 | 否 | 2–8× 工程提升，无协议变化 |
| A：mask-hint 降维 | `H_mask = D^T A_mask`，维度 `n_mask` | 替换 H2，部分降低 | 新 hint；n_mask 安全/性能权衡 |
| B：BFV/LinPIR 辅助 | 仅 BFV 密钥 | 是 | BFV 开销；D^T 的 LinPIR 数据库 |

**建议**：先做 C（安全、低风险），再原型 A（轻量、可量化），最后视需要做 B（真正消除）。

---

## 4. 路线 C：安全的客户端工程优化（先做）

### 4.1 批量矩阵-矩阵乘

当前是 40 次 `H2 × sk_i`。改为：

```text
SK = [sk_0, ..., sk_39]        // n_off × 40
MASK = H2 × SK                 // m × 40
```

`decrypt_preproc64` 目前每次内部计算 `H_2 * sk`；新增一个批量接口：

```cpp
absl::StatusOr<std::vector<Matrix64>> ComputeHintTimesSecrets(
    const Matrix64& H2, const std::vector<Matrix64>& sks);
```

这样可以利用 cache 和矩阵-矩阵乘的优化，通常 2–4×。

### 4.2 并行

40 行彼此独立；在 `PreprocRecoverZNew64` 中用 OpenMP 或 `std::thread` 并行。8 核上可接近 5–8×。

### 4.3 流式 H2

`H2` 是 `m × n_off`；客户端可以按 block 读取：

```text
for each block of H2 rows:
    acc += H2_block × SK
```

峰值内存从 `O(m·n_off)` 降到 `O(B·n_off + m)`。时间不变，但对 4 GiB 和 ARM 很重要。

### 4.4 64-bit 模运算

`decrypt_preproc64` 的 64-bit 模乘/除是热点；可使用 Montgomery/Solinas 约减或 SIMD。该优化不改变协议。

### 4.5 验收

- 正确性：与 baseline 的 `Z` 完全一致（逐元素比较）；
- 时间：`offline_recover_Z` 有可测量下降；
- 内存：流式版本的峰值 RSS 下降；
- 不改变 `H2`/`Z'`/`C'` 语义。

> **不要做**单密钥复用（40 行共用一个 `sk`）。当前 40 行复用同一个公开 pad `A2`；共用密钥后服务器可计算 `b_i - b_j = (e_i-e_j) + Δ(C_i-C_j)`，恢复 `C` 的行差，破坏 soundness。

---

## 5. 路线 A：mask-hint 降维（轻量 LHE，推荐先原型）

### 5.1 思路

引入一个独立的 mask LHE，维度 `n_mask`，以及对应的 mask pad `A_mask`（`rows × n_mask`）：

1. 客户端计算 `pre_i = A2 · sk_i`（长度 rows），使用结构化 NTT；
2. 客户端用 `A_mask, sk_mask` 加密 `pre_i`；
3. 服务器计算 `D^T c_i`；
4. 服务器一次性计算并发布 `H_mask = D^T A_mask`（`cols × n_mask`）；
5. 客户端用 `H_mask, sk_mask` 解密得到 `H2 sk_i`；
6. 客户端从服务器响应中减去 `H2 sk_i`，恢复 `Z_i`。

客户端持有 `H_mask`（`cols × n_mask`）而不是 `H2`（`cols × n_off`）。当 `n_mask < n_off` 时，客户端 hint、客户端解密时间、服务器 `H_mask` 计算都按比例下降。

### 5.2 复杂度

| 项 | 当前 | 路线 A |
|---|---|---|
| 客户端 hint | `cols × n_off` | `cols × n_mask` |
| 客户端解密 | `40 · cols · n_off` | `40 · cols · n_mask` + `40 · cols` |
| 服务器 H2/H_mask | `N × n_off` | `N × n_mask` |
| 服务器 per-client | `40 · N` | `2 × 40 · N`（响应 + mask） |

收益近似线性于 `n_mask / n_off`。例如 `n_mask = 512` 时 hint/客户端解密约为原来的 18%；但**必须**先证明 `n_mask = 512` 的 mask LWE 满足目标安全级别。

### 5.3 安全分析任务

- mask LWE 的实例：密钥 `sk_mask`（长度 `n_mask`）、pad `A_mask`、明文 `pre_i = A2 sk_i`（mod q，值较大）；
- 服务器视图：`H_mask = D^T A_mask`、`c_i`、`D^T c_i`、原响应；
- 需要确认：
  1. mask LWE 在 `n_mask`、模数、误差、明文大小下达到 128-bit（使用旧仓库的 Lattice Estimator 工具）；
  2. `H_mask` 不泄漏 `D` 的超额信息；
  3. `pre_i` 的分布/大小不会破坏 LWE 安全性；
  4. mask 解密误差 < `Δ_mask/2`，并能精确恢复 `H2 sk_i` mod q。
- 如果 `n_mask` 必须接近 `n_off`，路线 A 的收益有限，应转向路线 B 或 C。

### 5.4 实现步骤

1. **参数**
   - 在 `hintless_simplepir/parameters.h` 增加：
     ```cpp
     enum class OfflineHintMode { kClientHint = 0, kMaskHint = 1, kFheAided = 2 };
     OfflineHintMode offline_hint_mode = OfflineHintMode::kClientHint;
     int mask_lwe_dimension = 0;
     int mask_plaintext_bits = 0;
     ```
   - 在 manifest/profile 中增加对应字段（或先做 CLI 参数）。

2. **mask LHE**
   - 复用 `LHE`/`Multi_Limb_LHE`；新增 mask 专用实例；
   - 客户端生成 `sk_mask`，服务器不需要它；
   - 生成 `A_mask`（可 seed 派生）。

3. **客户端 pre-mask**
   - 新增：
     ```cpp
     absl::StatusOr<Matrix64> ComputeOfflinePadTimesSecret(
         const Parameters& params,
         absl::string_view public_seed,
         const Matrix64& secret);
     ```
   - 结构化：调用 `YpirOfflinePreprocessor::Create` + `ComputePadTimesSecret`；
   - dense：用 `A_2` 做 `matMulVec64`。

4. **服务器 mask 响应**
   - 新增：
     ```cpp
     absl::StatusOr<std::vector<Matrix64>> TransposeProductMaskCiphertexts64(
         const std::vector<Matrix64>& mask_cts);
     ```
   - 复用 `PreprocAnswerNew64`/`TransposeProductCiphertexts64` 的 `D^T` 逻辑。

5. **客户端恢复 Z**
   - 新增：
     ```cpp
     Matrix PreprocRecoverZWithMask(
         const Matrix64& H_mask,
         const std::vector<Matrix64>& sk_masks,
         const std::vector<Matrix64>& mask_cts,
         const std::vector<Matrix64>& res_cts,
         const std::vector<Matrix64>& sks,
         uint32_t blowup);
     ```
   - 先解 mask，再减响应，再除以 `Delta64_preproc`。

6. **实验驱动**
   - 在 `pir_experiment.cc` 增加 `--offline-hint-mode=mask`；
   - 跳过 `H_2` 的生成/转换；
   - 生成 `H_mask`（服务器一次性）并传给客户端；
   - 记录 mask 阶段时间。

7. **验收**
   - 客户端不再调用 `H2 × sk`；
   - 记录/比较 `H_mask` 大小、客户端时间、服务器时间；
   - 三个验证等式通过；
   - 安全分析文档完成。

### 5.5 风险

- `n_mask` 的安全/性能平衡可能不理想；
- mask 明文 `pre_i` 较大，可能需要多 limb；
- 服务器 `H_mask` 计算是 `N × n_mask`，如果 `n_mask` 不够小，收益有限；
- `H_mask` 是一个新的数据库相关 hint，方向 3 更新时必须更新它（见 §8）。

---

## 6. 路线 B：BFV/LinPIR 辅助解密（真正消除 H2）

### 6.1 思路

使用已有的 BFV/LinPIR 基础设施，让客户端不需要任何数据库相关 hint：

1. 客户端计算 `pre_i = A2 sk_i`；
2. 客户端用 BFV 公钥加密 `pre_i`（必要时多 limb/CRT）；
3. 服务器使用 **D^T 的 LinPIR 数据库** 计算
   ```text
   D^T · Enc(pre_i) = Enc(D^T pre_i) = Enc(H2 sk_i)
   ```
4. 客户端用自己的 BFV 私钥解密，得到 `H2 sk_i`；
5. 客户端从原响应中减去，恢复 `Z`。

客户端不持有 `H2` 或 `H_mask`；BFV 的 evaluation key/Galois keys 是公开参数，与 `D` 无关。

### 6.2 关键挑战

- `pre_i` 是 mod q 的大值（离线模数约 54 bit）；BFV 明文模数需要足够大，或使用多 limb；
- 服务器需要为 `D^T` 建立 LinPIR 数据库，大小 `O(N)`；它可以一次性建立并复用；
- 服务器每客户端要做一次 LinPIR 矩阵-向量乘，成本可能高于现有 `D^T C^T`；
- 客户端 BFV 加密/解密开销需要实测；
- 噪声/参数必须重新分析（旧仓库 security 模块）。

### 6.3 实现步骤

1. 复用 `linpir` 的 `Database`/`Server`；
2. 从 `database.DataTranspose()` 建立 `D^T` 的 LinPIR 数据库；
3. 客户端生成 BFV 密钥，加密 `pre_i`；
4. 服务器 `HandleRequest` 计算 `D^T · Enc(pre_i)`；
5. 客户端解密 mask，减去响应；
6. 记录服务器/客户端时间、内存、通信；
7. 与路线 A/C 对比，选择论文主方案。

### 6.4 风险

- BFV 开销可能抵消收益；
- `D^T` 的 LinPIR 数据库存储/预处理可能很大；
- 明文模数/多 limb 复杂；
- 客户端 BFV 密钥管理比 LHE 复杂。

---

## 7. 推荐实施路线

### Phase 0：基线与 instrumentation

- 在 `pir_experiment.cc` 增加 stage timing：
  - `client_premask_compute`
  - `client_mask_encrypt`
  - `server_mask_transpose_product`
  - `client_mask_decrypt`
- 用 128 MiB / `negacyclic-both` 记录 baseline。

### Phase 1：路线 C（必须完成）

- 批量 `H2 × SK`；
- 并行；
- 流式 H2；
- 64-bit 模运算（可选）。
- 目标：安全、可测量的 2–8× 改进，作为 fallback。

### Phase 2：路线 A 原型

- 参数 `n_mask` 先取 `n_off`（验证正确性），再逐步降低；
- 先 dense A2，后结构化 A2；
- 测客户端/服务器/hint 大小；
- 用旧 security 模块分析 `n_mask` 安全性。
- 决策点：如果 `n_mask` 不能明显小于 `n_off`，路线 A 只能作为部分优化。

### Phase 3：路线 B（如需要真正消除 H2）

- 先做单行 mask 的小规模原型；
- 再扩展到 40 行；
- 测 BFV 开销与 LinPIR 数据库构建；
- 与 A/C 对比。

### Phase 4：profile/manifest/报告

- 增加 `offline_hint_mode`（`client-hint` / `mask-hint` / `fhe-aided`）；
- 更新 `manifests/paper-v1.json`、`experiments/paper_config.py`、`scripts/lib/report.sh` 的必要字段（不要重新引入内存门槛）；
- 更新 `experiments/summarize_results.py` 的指标解析；
- 新增实验矩阵。

### Phase 5：测试与验收

- 新增单元测试（当前项目没有 tests）：
  - `pre_i = A2 sk_i` 与 `ComputePadTimesSecret` 一致；
  - mask 解密等于 `H2 sk_i`；
  - `Z` 与 baseline 逐元素一致；
  - 三个验证等式通过；
  - 选择的模式下不分配 `H2`。
- 集成测试：128 MiB 四种 profile。

---

## 8. 与方向 3 的接口

如果同时做方向 3（增量更新）：

- **路线 A**：`H_mask = D^T A_mask` 是新的数据库相关 hint。更新 `D[r,c] += Δ` 时：
  ```text
  H_mask[c, :] += Δ · A_mask[r, :]
  ```
  客户端必须更新 `H_mask`（O(n_mask) per cell）；服务器也要更新。
- **路线 B**：没有 `H_mask`/`H2`；更新 `D` 后，服务器需要更新 `D^T` 的 LinPIR 数据库（或只更新受影响的行/列），客户端不需要新 hint。
- **路线 C**：仍持有 `H2`；更新 `H2[c,:] += Δ A2[r,:]`。
- 组合建议：
  - 若目标是“动态 + 小客户端”，路线 B + 方向 3 最干净（无离线 hint）；
  - 若路线 B 太重，路线 A + 方向 3 需要额外的 `H_mask` 更新；
  - 路线 C 只能作为 baseline。

---

## 9. 文件级改动清单

| 文件 | 改动 |
|---|---|
| `hintless_simplepir/parameters.h` | `OfflineHintMode`、`n_mask`、mask 参数 |
| `hintless_simplepir/offline_preprocessor.{h,cc}` | 客户端 `ComputeOfflinePadTimesSecret`；服务器 `H_mask` 计算 |
| `hintless_simplepir/server.cc` | mask 密文的 `D^T`；`H_mask` 生成/更新 |
| `hintless_simplepir/client.{h,cc}` | mask 解密、`Z` 恢复；状态记录 |
| `hintless_simplepir/pir_experiment.cc` | `--offline-hint-mode`；跳过 H2；新 stage timing |
| `verisimplepir/src/lib/pir/preproc_pir.{h,cpp}` | mask 消息/响应/恢复 API |
| `verisimplepir/src/lib/pir/lhe.{h,cpp}` | mask LHE 实例/解密 |
| `verisimplepir/src/lib/pir/multilimb_lhe.{h,cpp}` | 大明文/多 limb |
| `linpir/database.{h,cc}`、`linpir/server.{h,cc}` | 路线 B 的 `D^T` LinPIR |
| `experiments/paper_config.py`、`experiments/run_matrix.py` | 新模式/参数 |
| `experiments/summarize_results.py` | 新 stage/metrics |
| `manifests/paper-v1.json` | `offline_hint_mode`/mask 参数（可选） |
| `scripts/lib/report.sh` | 新模式 marker |
| `docs/plans/direction-3-...md` | 更新联动说明 |

---

## 10. API 草案（C++）

```cpp
enum class OfflineHintMode {
  kClientHint = 0,   // 当前：客户端持有 H2
  kMaskHint = 1,     // 路线 A
  kFheAided = 2,     // 路线 B
};

struct MaskParameters {
  int lwe_dimension = 0;
  int plaintext_bits = 0;
  int limbs = 1;
};

// 客户端：A2 * secret（结构化或 dense）
absl::StatusOr<Matrix64> ComputeOfflinePadTimesSecret(
    const Parameters& params,
    absl::string_view public_seed,
    const Matrix64& secret);

// 客户端：生成 mask 消息
struct MaskClientMessage {
  std::vector<Matrix64> challenge_cts;
  std::vector<Matrix64> mask_cts;
  std::vector<Matrix64> challenge_sks;
  std::vector<Matrix64> mask_sks;
};
absl::StatusOr<MaskClientMessage> PreprocClientMessageMask(
    const Parameters& params,
    const Matrix64& A2,
    const BinaryMatrix& C,
    const MaskParameters& mask_params);

// 服务器：D^T 同时作用于挑战和 mask
struct MaskServerResponse {
  std::vector<Matrix64> challenge_response_cts;
  std::vector<Matrix64> mask_response_cts;
};
absl::StatusOr<MaskServerResponse> PreprocAnswerMask(
    const Server& server,
    const MaskClientMessage& message);

// 客户端：恢复 Z
absl::StatusOr<Matrix> PreprocRecoverZMask(
    const MaskServerResponse& response,
    const MaskClientMessage& message,
    const Matrix64& H_mask_or_empty,
    uint32_t blowup);
```

> 实际签名可按现有 `Matrix64`/`Matrix` 类型调整；关键是保持 `challenge` 与 `mask` 两条密文流分离。

---

## 11. 测试与验收标准

### 正确性

- [ ] `pre_i == A2 · sk_i`（结构化与 dense 两条路径）；
- [ ] mask 解密得到 `H2 · sk_i`（与 baseline 的 `H2*sk` 逐元素一致）；
- [ ] `Z` 与 baseline 逐元素一致；
- [ ] `Z'A = C'H`、`C'w = Z'As`、`C'v = Z'u` 全部通过；
- [ ] 最终记录与数据库记录一致。

### 安全/参数

- [ ] mask LWE 的维度/模数/误差满足目标安全级别；
- [ ] 多 limb/明文模数的噪声分析；
- [ ] mask hint 不泄漏额外信息；
- [ ] 恶意服务器返回错误 mask/resp 时客户端拒绝（测试）。

### 性能

- [ ] 客户端 `offline_recover_Z` 时间下降；
- [ ] `H2` 存储/传输下降或消除；
- [ ] 服务器 per-client 时间在可接受范围；
- [ ] 端到端预处理时间与 baseline 对比；
- [ ] 峰值 RSS 记录。

---

## 12. 实验矩阵

| 模式 | 尺寸 | profile | 备注 |
|---|---|---|---|
| baseline | 128mib/256mib/512mib/1gib | dense/negacyclic-both | 对照 |
| C：batch/parallel/stream | 同上 | 同上 | 安全工程优化 |
| A：n_mask = n_off/2, n_off/4, 512, 1024 | 128mib/256mib | negacyclic-offline/both | 权衡 |
| B：BFV/LinPIR | 128mib/256mib | negacyclic-offline/both | 真正消除 |
| 2gib/4gib | 内存允许时 | 最优模式 | 规模验证 |

指标：客户端/服务器时间、峰值 RSS、hint 大小、上传/下载、正确性、安全参数。

---

## 13. 风险与降级方案

| 风险 | 降级 |
|---|---|
| mask LWE `n_mask` 无法安全降维 | 路线 A 仅作部分优化；转 B 或 C |
| mask 明文过大/噪声不足 | 多 limb、增大模数、CRT |
| 服务器 `H_mask` 计算太慢 | 选择更小 `n_mask`；或 B |
| BFV 开销太大 | 回退 A/C |
| 客户端仍持有 `H_mask` | 明确论文中“降维 hint”而非“无 hint” |
| `H` 仍占用客户端内存 | 额外的 server-aided `C'H` 或流式 `H`（另立变体） |

---

## 14. 论文贡献映射

- **路线 C**：工程/测量贡献（可作为 baseline 或系统章节）；
- **路线 A**：**hint 维度与离线解密成本的显式权衡**；新参数 `n_mask`；安全/性能曲线；
- **路线 B**：**真正消除离线 hint**；利用 BFV/LinPIR 和结构化 `A2`；新的协议变体与安全证明；
- 组合：如果 B 可行，论文主线是“消除 H2”；如果 B 太重，A 的权衡曲线 + C 的工程优化也可成文，但要诚实表述。

---

## 15. 里程碑

| 阶段 | 产出 | 预计 |
|---|---|---|
| P0 | baseline timing + 测试骨架 | 1–2 天 |
| P1 | 路线 C（batch/parallel/stream） | 3–5 天 |
| P2 | 路线 A 正确性原型（n_mask = n_off） | 1 周 |
| P3 | 路线 A 降维 + 安全分析 | 1–2 周 |
| P4 | 路线 B 原型（单行/40 行） | 2–4 周 |
| P5 | 实验矩阵/总结 | 1 周 |
| P6 | 论文写作 | 2–4 周 |

> 建议在 P2 完成后做一次 go/no-go：如果 `n_mask` 不能低于 `n_off/2`，优先转 P4 或把论文重点放在方向 3。
