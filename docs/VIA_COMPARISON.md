# VIA 后期对比方案

## 为什么 VIA 现在只是对照

VIA 的优势是服务器侧/静默预处理、客户端不保存数据库规模相关 PIR hint，以及较轻的已报告预处理。它适合作为工程性能竞争者。但 VIA 的现有安全定义是查询隐私与诚实正确性，不等同于 Small-client vPIR 的恶意服务器响应一致性和 selective-failure 防护。

若第一版采用 VIA，必须再实现并证明恶意编译层；这会引入 LDC/proximity test、向量承诺、keyword-PIR 适配及更大的预处理常数。因此在“最低密码学创新风险”目标下，VIA 不应做主干。

## 公平比较的两条轨道

1. **工程性能轨道**：原生 Small-client vPIR 对 plain VIA，明确标注安全模型不同。用于判断服务器侧预处理、在线延迟和客户端状态的工程潜力。
2. **同安全轨道**：原生 Small-client vPIR 对“VIA + 完整恶意安全层”。只有后者实际实现并验证后，才能判断哪个方案更适合恶意服务器部署。

不得把轨道 1 的 VIA 性能与轨道 2 的安全标签拼成一个结果。

## 统一指标

| 类别 | 必报字段 |
|---|---|
| 输入 | 逻辑 DB 字节、记录数、记录大小、矩阵布局、更新状态 |
| 安全 | LWE/RLWE/SIS 参数、目标 bit、恶意/半诚实、stateful、abort 语义 |
| DLP | 总时间、CPU 时间、峰值内存、server storage、pass 数 |
| CLP | server/client 时间、上下行字节、客户端峰值内存 |
| QLP | 每 token 时间、上下行字节、token 大小、是否可批处理 |
| Online | p50/p95/p99 延迟、吞吐、server work、上下行字节 |
| Client | 持久状态总量、短期峰值、公共参数、密钥和 metadata |
| 可复现性 | commit、profile digest、机器、线程、编译器、CPU flags、重复次数 |

## 决策规则

- 若应用必须在单恶意服务器下防 selective failure，优先选择通过 general-`H` 门禁的 Small-client vPIR，除非 VIA 的恶意版本已实际实现并有更好端到端结果。
- 若应用只需半诚实隐私，且客户端必须无数据库相关 PIR hint，VIA 可能更合适。
- 若 CLP 通信/时间是主要瓶颈，重点比较 Small-client 的一次性注册成本与 VIA server-only preprocessing，而不是只看 online。
- 若数据库频繁更新，两个第一版方案都不能直接宣称解决；需另立动态更新协议。

当前 benchmark schema 是 `pir-comparison-reference-v0`，只用于校验字段和代数控制流；它显式列出尚缺的分位数、CPU、峰值内存、吞吐和环境清单，因此 `comparison_ready=false`。只有补齐本节统一指标后才能升级正式 schema。VIA 的 [`../comparators/via/profile.json`](../comparators/via/profile.json) 明确为 `not-integrated`；基准命令只输出空占位，避免制造性能数字。

来源：[VIA, ePrint 2025/2074](https://eprint.iacr.org/2025/2074)。
