# 方向 3 改造指导：可增量更新的可验证预处理

- 状态：implementation guide（供后续改造使用，不是论文正文）
- 目标项目：`~/Faster-SCvPIR`
- 关联方向：`docs/plans/direction-1-server-aided-offline-decryption.md`
- 实测基线：128 MiB / `negacyclic-both`，全量预处理 43.07 s；客户端 `offline_recover_Z` 28.61 s

---

## 0. 目标、非目标与前置条件

### 目标（v1）

在数据库发生一批**保持尺寸的原地修改**后：

1. 服务器以 `O(B·(d0 + d2) + B·L)` 更新 `H`、`H2`（可选）、FHE/LinPIR 编码的 `H` 和数据库，而不是 `O(N·(d0+d2))`；
2. 客户端以 `O(γ·B)` **本地**更新压缩证明 `Z'`，不需要重新注册；
3. `C' = RC` 不变；
4. 三个验证等式 `Z'A = C'H`、`C'w = Z'As`、`C'v = Z'u` 在更新后仍然精确成立；
5. 更新由数据所有者签名；服务器仍可恶意；查询可以 pin 版本；
6. 明确泄漏：更新会泄漏位置、类型、数量和结构。

### 非目标（v1）

- 强删除（strong deletion）；
- 任意位置插入/重排/索引移动；
- 私有更新（隐藏更新位置/内容）；
- 多写者/拜占庭更新权威（先支持单权威签名）；
- 同时优化 dense 与结构化两条路径（优先结构化 profile）。

### 前置条件

- 已能运行 `make paper-run SIZE=128mib PROFILE=negacyclic-both`；
- 建议从旧仓库恢复：
  - `~/Faster-SCvPIR-rewritten/native/security/`（参数/安全分析）；
  - `~/Faster-SCvPIR-rewritten/docs/plans/` 中的旧版增量更新草稿（可参考其代数与文献表）。
- 当前精简项目没有 `tests/`；实现时必须新增更新正确性与版本一致性测试。

---

## 1. 实测基线与为什么需要增量更新

| 阶段 | 时间 |
|---|---:|
| 总预处理 | 43.07 s |
| 服务器全局 | 10.93 s |
| 客户端 `offline_recover_Z` | 28.61 s |
| Prepare + Online | 0.17 s |

任何数据库更新如果触发全量重建，就要重复上述 43 秒（以及客户端重新注册）。对于周期性小批量更新，这不可接受。增量更新的目标是让更新成本与 `B`（变更 cell 数）而不是 `N` 成正比。

---

## 2. 当前代码路径（精确到函数）

### 2.1 服务器状态

| 文件/函数 | 作用 |
|---|---|
| `hintless_simplepir/database_hwy.{h,cc}` | `D` 的列布局、转置布局、packed byte 存储；`Data()`、`DataTranspose()`、`SetHints()` |
| `hintless_simplepir/main_preprocessor.{h,cc}` | `ComputeHint(D)` -> `H = D·A`；`ComputePadTimesSecret`；`MultiplyRightByPad` |
| `hintless_simplepir/offline_preprocessor.{h,cc}` | `ComputeHint(D)` -> `H2 = D^T A2`；`ComputePadTimesSecret`；`EncryptChallenges` |
| `hintless_simplepir/server.cc` | `PreprocessBSGS`（H + LinPIR/FHE 编码）；`TransposeProductCiphertexts64`；`HandlePrepareRequestBSGS`；`HandleRequestSkipLinPir` |
| `linpir/database.{h,cc}` | `diagonals_`、`diagonals_bsgs_`、`pad_inner_products_*`；`CreateBSGS`、`PreprocessBSGS`、`InnerProductWithPreprocessedPadsBSGS` |
| `linpir/server.{h,cc}` | BSGS 预处理 pad（baby/giant）；`HandleRequestBSGS` |

### 2.2 客户端状态

| 文件/函数 | 作用 |
|---|---|
| `hintless_simplepir/pir_experiment.cc` | 采样 `C`、`R`；计算 `RC = C'`、`RZ = Z'`；验证 |
| `hintless_simplepir/client.{h,cc}` | `MultiplyRightByMainPad`；恢复记录 |
| `verisimplepir/src/lib/pir/preproc_pir.{h,cpp}` | `PreprocRecoverZNew64`、`PreprocClientMessageNew64` |

当前长期状态只统计 `RZ`（`Long Term State`）。**更新需要 `C'`**；论文中必须把 `C'` 计入客户端状态（`γ × rows`，仍然很小）。

---

## 3. 更新模型、参与者与威胁

### 参与者

- **数据所有者（owner）**：setup 时可信；对每次批量变更生成签名更新日志；
- **服务器**：setup/注册后可以恶意；
- **客户端**：验证者，持有 `Z'`、`C'`，可以指定版本。

### 更新条目

```text
op = (r, c, Δ, k, prev_hash, signature)
```

- `r, c`：cell 坐标；
- `Δ`：新值减旧值（mod 256）；
- `k`：版本号，单调递增；
- `prev_hash`：前一条日志的哈希；
- `signature`：数据所有者签名。

### 威胁

- 服务器：漏更新、乱序、回滚、equivocation、返回 stale 数据；
- 服务器：在查询响应中不一致地使用更新后的状态；
- 客户端/攻击者：伪造更新（签名阻止）。

### 泄漏函数

```text
L(op) = (|op|, type(op), position(op), structure(op))
```

- 修改操作可能泄漏 `Δ`；
- 删除操作可以用随机值隐藏旧值；
- 服务器的视图不超过 `L`。

---

## 4. 更新代数

对一次 cell 修改 `(r, c, Δ)`。

### 4.1 数据库

```text
D[r, c] += Δ
```

同时更新：

- 列布局；
- 转置布局（`D^T` 用于 `H2`/离线路径）；
- stacking 时更新对应 stack。

### 4.2 主 hint

```text
H[r, :] += Δ · A[c, :]
```

- `A` 是主 pad（`db_cols × main_dim`）；
- 结构化 `A` 下，`A[c,:]` 是 block-negacyclic 行，更新 O(d0)；
- 同一行多个更新可以聚合：
  ```text
  H[r, :] += Σ_c Δ_c · A[c, :]
  ```

### 4.3 离线 hint（若保留）

```text
H2[c, :] += Δ · A2[r, :]
```

- `A2` 是离线 pad（`db_rows × offline_dim`）；
- 结构化 `A2` 下 O(d2)；
- 同一列多个更新可以聚合。

> 如果先实现了方向 1 的 server-aided / FHE-aided 模式，`H2` 可能不存在，本步骤可以跳过；但 `H_mask`（方向 1 路线 A）需要相应更新：
> ```text
> H_mask[c, :] += Δ · A_mask[r, :]
> ```

### 4.4 FHE/LinPIR 编码

`H` 的行变化会影响 LinPIR 的 diagonal/BSGS 编码和预处理 pad。需要更新：

- `linpir::Database::diagonals_` / `diagonals_bsgs_`；
- `LinPirServer` 的 baby/giant pads；
- 只更新受影响的 block/coefficient，代价记为 `L`。

这是方向 3 的**核心难点**，详见 §5。

### 4.5 客户端 Z'

```text
Z'[:, c] += Δ · C'[:, r]
```

推导：

```text
Z = C·D
D[r,c] += Δ  =>  Z[:,c] += Δ·C[:,r]
Z' = R·Z     =>  Z'[:,c] += Δ·(R·C)[:,r] = Δ·C'[:,r]
```

- `C'` 不变；
- 每次更新 O(γ)；
- 不需要交互、不需要重新压缩、不需要重新注册。

---

## 5. 更新友好的 FHE/LinPIR 编码

### 5.1 当前结构

`linpir::Database` 保存：

```text
diagonals_            // H 的 diagonal 分块
diagonals_bsgs_       // BSGS 的 diagonal 分块
pad_inner_products_*  // 预处理 pad
```

`LinPirServer` 保存：

```text
ct_pads_*             // 密文 pad
gk_pads_*             // Galois key pad
pad_inner_products_*  // 预处理内积 pad
```

### 5.2 一次更新影响什么

- `H` 的一行变化 `Δ·A[c,:]`；
- 在 diagonal 表示中，每个 diagonal 最多改一个系数；
- 受影响的 diagonal 数约为 `rows_per_block`；
- 受影响的 BSGS block 数取决于更新行落在哪个 baby/giant 块。

### 5.3 设计目标

实现：

```text
单 cell：O(d0 + L)
批量 B：O(#affected rows · d0 + #affected cols · d2 + B·L)
```

而不是 `O(N)`。

### 5.4 三种可选实现

| 方案 | 做法 | 代价 | 风险 |
|---|---|---|---|
| 精确增量 | 直接修改受影响的 diagonal/pad 系数 | O(block) | 需要理解 BSGS pad 的线性结构 |
| 块重建 | 只重建受影响的 baby/giant block | O(block·K) | 实现简单，需实测 |
| Delta 编码 | 保存基础编码 + delta 列表，查询时叠加 | 查询变慢 | 适合小更新多查询 |

**建议先做“块重建”**：它比精确增量简单，能快速验证 `L` 是否可接受；如果 `L` 太大，再优化为精确增量。

### 5.5 原型步骤

1. 在 `linpir::Database` 增加：
   ```cpp
   absl::Status ApplyRowUpdate(int64_t row, const std::vector<RlweInteger>& delta);
   ```
2. 在 `LinPirServer` 增加：
   ```cpp
   absl::Status ApplyDatabaseUpdate(...);
   ```
3. 先只支持单 shard、单 modulus、单 block；
4. 测 `ApplyRowUpdate` 时间；
5. 扩展到多 shard/多 modulus；
6. 与全量 `PreprocessBSGS` 对比，得到 `L` 和 break-even batch size。

> 如果 `L` 无法做到 `o(N)`，方向 3 的论文卖点会大打折扣；这是第一个 go/no-go 点。

---

## 6. 客户端状态与 Z' 更新

### 6.1 状态

```text
Z'  : γ × columns
C'  : γ × rows
version : uint64
```

- `C'` 可以存储，也可以由 `R`、`C` 重新生成；更新路径建议直接存储 `C'`；
- `R`、`C` 不需要参与更新；
- `Z'` 是长期秘密状态。

### 6.2 更新 API

```cpp
struct ClientUpdate {
  int64_t row;
  int64_t col;
  int32_t delta;
  uint64_t version;
};

absl::Status Client::ApplyUpdate(const ClientUpdate& op);
```

实现：

```cpp
for (int i = 0; i < Z_prime.rows; ++i) {
  Z_prime(i, op.col) += op.delta * C_prime(i, op.row);
}
version = op.version;
```

### 6.3 验证

更新后：

```text
Z'A = C'H       // 使用更新后的 H（或 server-aided C'H）
C'w = Z'As
C'v = Z'u
```

由于 `Z'` 和 `H` 都按同一线性规则更新，等式仍然成立。需要测试逐元素一致性。

---

## 7. 签名更新日志与版本

### 7.1 数据结构

```cpp
struct UpdateEntry {
  int64_t row;
  int64_t col;
  int32_t delta;
  uint64_t version;
  std::array<uint8_t, 32> prev_hash;
  std::vector<uint8_t> signature;
};
```

### 7.2 签名

- 推荐 Ed25519（OpenSSL EVP 支持）；
- 数据所有者生成密钥对；
- setup 时客户端/服务器获得公钥；
- 每条日志签名；客户端和服务器验证。

### 7.3 哈希链

```text
h_k = H(entry_k || h_{k-1})
```

- 防止乱序/回滚/equivocation；
- 客户端检查 `version` 单调递增；
- 服务器在查询响应中携带当前版本；
- 客户端拒绝旧版本。

### 7.4 Protobuf 扩展

在 `hintless_simplepir/serialization.proto` 中增加：

```proto
message HintlessPirRequest {
  ...
  uint64 version = N;
}
message HintlessPirResponse {
  ...
  uint64 version = N;
}
```

- 版本字段需要参与服务器/客户端的一致性检查；
- 注意 protobuf 向后兼容。

### 7.5 多写者（v2）

- 阈值签名；
- 或对齐 UVPIR 的 permissioned updates；
- 不在 v1 范围。

---

## 8. 安全模型与证明目标

建议定义 **UVPIR for SCvPIR**。

### 正确性

服务器诚实且客户端使用版本 `k` -> 客户端得到 `D_k[index]`。

### Soundness

任何 PPT 恶意服务器不能使客户端接受错误记录，除非以可忽略概率。

### Privacy

- 查询索引隐藏（继承 SCvPIR）；
- 服务器视图不超过 `L(op)`；
- 更新日志的签名/哈希不泄漏额外数据。

### 版本一致性

- 客户端和服务器对版本 `k` 一致；
- 服务器不能提供 stale 数据而不被检测；
- 哈希链抗碰撞 + 签名不可伪造 + 版本 pin。

### 证明思路

1. 正确性：更新代数 + 线性性；
2. Soundness：SCvPIR 原有 soundness + 签名不可伪造 + 哈希链抗碰撞；
3. Privacy：SCvPIR query privacy + 显式泄漏函数；
4. 版本：哈希链 + 客户端检查 + 服务器响应绑定。

---

## 9. 实施路线

### Phase 0：基线与测试骨架

- 在 `pir_experiment.cc` 增加更新模式：
  - 注册 -> 应用 B 个更新 -> 查询 -> 校验；
- 新增测试目录（当前项目没有 tests）：
  - 单 cell 更新；
  - 同行/同列批量；
  - 版本检查；
  - 恶意服务器（漏更新、乱序、回滚）。

### Phase 1：数据库更新

- `database_hwy` 增加：
  ```cpp
  absl::Status ApplyUpdate(int64_t row, int64_t col, int32_t delta);
  ```
- 更新列布局、转置布局、stacking；
- 测试 `Record`/`RecordWithStacking`。

### Phase 2：H 更新

- `main_preprocessor`/`Database` 增加：
  ```cpp
  absl::Status ApplyHintRowUpdate(int64_t row,
                                  const std::vector<uint8_t>& deltas);
  ```
- 结构化 `A`：直接改 `H[r,:]`；
- 测试与全量 `ComputeHint` 的一致性。

### Phase 3：客户端 Z' 更新

- 在客户端状态中保存 `C'`；
- 增加 `ApplyUpdate`；
- 测试 `Z'` 与全量重建一致；
- 更新 `Long Term State` 统计（加入 `C'`）。

### Phase 4：FHE/LinPIR 编码更新（核心）

- 先做块重建；
- 测 `L`；
- 如果可接受，再做精确增量；
- 测试更新后 `H·s` 与全量重建一致；
- 这是 go/no-go 点。

### Phase 5：H2 / H_mask 更新

- 如果保留 `H2`：`H2[c,:] += Δ A2[r,:]`；
- 如果采用方向 1 路线 A：`H_mask[c,:] += Δ A_mask[r,:]`；
- 如果采用方向 1 路线 B：无 H2/H_mask，跳过；
- 客户端相应更新 hint（如果它持有）。

### Phase 6：签名日志/版本

- 新增 `hintless_simplepir/update_log.{h,cc}`；
- Ed25519 签名/验证；
- 哈希链；
- protobuf 版本字段；
- 客户端版本检查；
- 服务器版本 pin。

### Phase 7：实验与恶意服务器测试

- B = 1, 10, 100, 1000, 1% 列, 1% 全库；
- 对比 43 s 全量重建；
- 恶意服务器测试；
- 记录 break-even batch size。

### Phase 8：论文材料

- 复杂度定理；
- 安全证明；
- 实验表格。

---

## 10. 文件级改动清单

| 文件 | 改动 |
|---|---|
| `hintless_simplepir/database_hwy.{h,cc}` | `ApplyUpdate`；双布局/stacking |
| `hintless_simplepir/main_preprocessor.{h,cc}` | `ApplyHintRowUpdate`；结构化/dense |
| `hintless_simplepir/offline_preprocessor.{h,cc}` | H2/H_mask 更新（可选） |
| `hintless_simplepir/server.cc` | `ApplyUpdate` 编排；FHE/LinPIR 更新；版本 pin |
| `linpir/database.{h,cc}` | `ApplyRowUpdate`；diagonal/BSGS/pad 更新 |
| `linpir/server.{h,cc}` | BSGS pad 更新 |
| `hintless_simplepir/client.{h,cc}` | `ApplyUpdate`；`C'` 状态 |
| `hintless_simplepir/update_log.{h,cc}` | 新模块：日志、签名、哈希链 |
| `hintless_simplepir/serialization.proto` | 版本字段 |
| `hintless_simplepir/pir_experiment.cc` | 更新实验流程 |
| `experiments/paper_config.py`、`run_matrix.py` | 更新 workload/模式 |
| `experiments/summarize_results.py` | 更新指标 |
| `manifests/paper-v1.json` | 更新批次/模式字段（可选） |
| `docs/plans/direction-1-...md` | 联动说明 |

---

## 11. API 草案（C++）

```cpp
struct UpdateEntry {
  int64_t row;
  int64_t col;
  int32_t delta;
  uint64_t version;
  std::array<uint8_t, 32> prev_hash;
  std::vector<uint8_t> signature;
};

class UpdateLog {
 public:
  absl::Status Append(const UpdateEntry& entry);
  absl::Status VerifyChain(uint64_t from_version) const;
  absl::Status VerifySignature(const UpdateEntry& entry,
                               absl::Span<const uint8_t> public_key) const;
  uint64_t version() const;
};

// Database
absl::Status ApplyUpdate(int64_t row, int64_t col, int32_t delta);

// Main hint
absl::Status ApplyHintRowUpdate(
    int64_t row, absl::Span<const int32_t> per_column_deltas);

// LinPIR encoding
absl::Status LinPirDatabase::ApplyRowUpdate(
    int64_t row, absl::Span<const RlweInteger> delta);

// Client
absl::Status Client::ApplyUpdate(const UpdateEntry& entry);
```

---

## 12. 测试与验收标准

### 正确性

- [ ] 单 cell 更新后 `D`、`H`、`H2`/`H_mask`、`Z'` 与全量重建逐元素一致；
- [ ] 批量更新后一致；
- [ ] 三个验证等式通过；
- [ ] `H·s` FHE 路径与全量重建一致；
- [ ] 更新后查询返回正确记录。

### 版本/安全

- [ ] 版本单调递增；
- [ ] 签名验证；
- [ ] 哈希链检测乱序/回滚；
- [ ] 恶意服务器漏更新/乱序/equivocation 被检测；
- [ ] 查询响应绑定版本。

### 性能

- [ ] 单 cell 更新时间；
- [ ] B=10/100/1000/1% 的更新时间；
- [ ] 与 43 s 全量重建的对比；
- [ ] break-even batch size；
- [ ] 客户端 `Z'` 更新时间；
- [ ] FHE 编码更新 `L`；
- [ ] 内存/存储开销。

---

## 13. 实验矩阵

| 维度 | 取值 |
|---|---|
| 尺寸 | 128mib, 256mib, 512mib, 1gib（内存允许时 2/4gib） |
| profile | dense, negacyclic-both（优先结构化） |
| 更新模式 | 单 cell；同行/同列；随机分散；1% 列；1% 全库 |
| B | 1, 10, 100, 1000, 1% N |
| 对照 | 全量重建；方向 1 的注册成本 |
| 恶意服务器 | 漏更新、乱序、回滚、错误版本、错误记录 |

指标：服务器/客户端更新时间、FHE 编码更新时间、验证时间、查询延迟、内存、日志大小、签名验证开销、break-even。

---

## 14. 风险与降级方案

| 风险 | 降级 |
|---|---|
| FHE/LinPIR 编码无法 O(block) 更新 | 块重建；或把论文重点放在 H/Z' 更新 + 外部 FHE 重建 |
| `L` 太大 | 减少支持的 profile；只做结构化；或论文只报告 H/Z' 的增量，FHE 作为限制 |
| 客户端 `C'` 状态增加 | 计入 state；仍很小 |
| 客户端仍持有 H/H2 | 结合方向 1 的 server-aided 验证/解密 |
| 版本/签名开销 | Ed25519 很快；日志批量签名 |
| 并发工作 | 先做文献核验（Lu et al. 2026/030、Guskind et al. 2026/1651、updatable PIR 2026/1590） |

---

## 15. 与方向 1 的协同

方向 1 和方向 3 可以组合成“动态 + 小客户端”的完整系统：

| 组合 | 注册 | 更新 | 客户端 hint |
|---|---|---|---|
| 方向 3 单独 | 43 s | H/H2/FHE/Z' 增量 | H2 仍存在 |
| 方向 1 路线 C + 方向 3 | 43 s（快 2–8×） | H/H2/FHE/Z' 增量 | H2 仍存在 |
| 方向 1 路线 A + 方向 3 | H2 替换为 H_mask | H/H_mask/FHE/Z' 增量 | H_mask |
| 方向 1 路线 B + 方向 3 | 无 H2/H_mask | H/FHE(D^T)/Z' 增量 | 无离线 hint |

推荐长期目标：**方向 1 路线 B + 方向 3**，即：

- 注册：客户端只持有 `Z'`、`C'`，没有 `H2`；
- 更新：服务器更新 `H`、FHE 编码和 `D`；客户端本地更新 `Z'`；
- 查询：版本 pin + 三个等式；
- 这是最干净的“server-side hints + tiny client”架构。

如果路线 B 太重，则路线 A + 方向 3 仍可成文，但必须把 `H_mask` 的更新纳入复杂度分析。

---

## 16. 论文贡献映射

1. 首个面向 SCvPIR **压缩证明状态 `Z'`、离线 hint `H2`、FHE 编码 `H`** 的增量更新协议；
2. 零交互客户端证明更新：`Z'[:,c] += Δ C'[:,r]`，`C'` 不变，无 NIZK、无重新注册；
3. update-friendly LinPIR/FHE 编码：服务器更新 `O(B(d0+d2)+B·L)`，而非 `O(N)`；
4. 签名更新日志 + 版本 pin，恶意服务器下的 soundness；
5. 实现与评估：以 43 s 全量重建为 baseline，给出不同 B 的加速比和 break-even；
6. 明确弱删除/任意插入/强删除/私有更新的边界。

---

## 17. 里程碑

| 阶段 | 产出 | 预计 |
|---|---|---|
| P0 | 测试骨架 + baseline | 2–3 天 |
| P1 | `D` 更新 | 3–5 天 |
| P2 | `H` 更新 | 1 周 |
| P3 | `Z'` 更新 + 客户端状态 | 1 周 |
| P4 | FHE/LinPIR 编码更新原型 | 2–4 周（go/no-go） |
| P5 | 签名日志/版本 | 1 周 |
| P6 | 实验矩阵/总结 | 1 周 |
| P7 | 论文写作 | 2–4 周 |

> 建议在 P4 完成后做 go/no-go：如果 `L` 不能显著小于 `N`，优先把论文重点放在“H/Z' 增量 + 结构化 FHE 重建”或转向方向 1。
