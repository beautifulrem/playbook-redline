# CODEX GOAL — Playbook Redline 后端 v2：「一条可独立验证的链，从 AI 改写直达真实成交」

> 喂给 Codex 执行的目标书。范围：**后端 + 架构**（前端本轮不管）。
> 运行方式建议：`codex exec --full-auto "$(cat CODEX_GOAL_BACKEND_V2.md)"`，或在 codex 交互态把本文件作为任务说明。
> 语言：正文中文，技术术语保留英文。所有 file:line 锚点来自 2026-06-24 的代码现状映射，开工前以实际代码为准复核。

---

## 0. 一句话使命（Mission）

把现有「确定性裁决 + 真实 Bitget demo 执行」升级为 **一条端到端、密码学链接、可被评委零密钥独立复核、leak-free 的证据链**：

> **edit → verdict(receipt) → approval → execution(真实 paptrading 成交) → attestation**，每一环都携带上一环的哈希，任何人改一个字节，`redline verify-chain` 当场变红并报出精确 violation code。

这条链是我们对所有竞品的护城河。**不要重写**现有系统（它已经很完整，~15.4k LOC + ~9k LOC 测试），这是**定向加固 + 补齐差异化**。

---

## 0.5 Loop Engineering 执行模型（本目标书「怎么被执行」，不只是「做什么」）

> 应用 2026 年的 **Loop Engineering** 范式（Peter Steinberger / Boris Cherny「我的工作是写 loop，不再 prompt」/ Addy Osmani；技术血脉 ReAct + Geoffrey Huntley 的 Ralph technique）。**不要**把本文件当一次性 prompt 跑完——把它当成一个**自驱动循环的 spec**：把人从「反复 prompt」里替换出来，由循环驱动 codex 迭代到「**确定性可验证的 done**」。

> **关键共振（必须内化）**：本项目 Redline 的信条是 *no proof, no verdict —— 不信自报、只信确定性验证*；Loop Engineering 的核心结论同样是 *"the verifier is the bottleneck — trust a deterministic verifier, never the agent's self-report"*。**所以：用 Redline 验策略的方式来验这个循环——fail-closed、确定性、绝不信 codex 自报「我做完了」。** 这份目标书自己也要吃自己的狗粮。

### 循环的 5 个构件（映射到本目标书）

1. **Goal（可度量的 done）**：每个 WS 的「确定性验收门」（下表），退出条件是**命令退出码**，不是 codex 的自评。
2. **Prompter**：每轮重新喂 `CODEX_GOAL_BACKEND_V2.md` + `CODEX_PROGRESS.md`（外部状态），让 codex 自己挑下一个未完成任务。
3. **Action**：codex 实现**一个**任务 + 一次提交（Ralph：一次一任务一 commit，fresh context，避免长会话漂移）。
4. **Verification（瓶颈，最重要）**：跑确定性 verifier（pytest / 纯度 gate / `verify-chain` / tamper-demo），**绿了才算数**；红了把失败输出回写状态文件，下一轮修。**绝不让 codex 自评通过。**
5. **Memory（外部状态）**：`CODEX_PROGRESS.md` 记录每任务 `todo|doing|done` + 最近一次 verifier 结果 + 一行人类可读 changelog；fresh-context 每轮**先读它**（智能来自「清晰 spec + 可验证产出 + 外部状态」，不是一个长 session）。

### 每个 WS 的确定性验收门（Verifier —— 循环只信这些命令的退出码，不信自然语言）

| WS | 确定性退出门（绿 = done） |
|---|---|
| A | `uv run pytest -k "next_bar or fees_slippage or tape_source or lookahead"` 全绿 |
| B | `uv run pytest -k "prev_hash or merkle or execution_evidence_links or attestation_covers or chain_break"` 全绿 |
| C | `uv run pytest -k "approval or self_approval or require_demo or non_reviewer"` 全绿 |
| D | `uv run pytest -k "reduce_size or release_tier or live_gated or risk_policy_reduce"` 全绿 |
| E | `uv run pytest -k "proof_tamper or distinct_codes or violation_catalog"` 全绿 + `python scripts/gen-violation-catalog.py --check` 退 0 |
| F | `scripts/release-demo.sh` 通过 + `uv run redline verify-chain <release_dir>` 退 0 + `scripts/tamper-demo.sh; test $? -ne 0`（tamper **必须**非零退出）|
| G | `python scripts/check-verdict-path-imports.py` 退 0 + `uv run pytest -k purity` 全绿 |
| 总门 | `uv run pytest -q` 全绿 **且** 第 5 节 DoD 全部命令绿 → 循环终止 |

### 外部状态文件 `CODEX_PROGRESS.md`（已预置在仓库根；codex 每轮维护）

每轮规则：**只做一个未完成任务 → 提交 → 跑该任务的确定性门 → 把 `last:` 回填为 `PASS/FAIL(摘要)` → 写一行 changelog**。门红则该任务保持未勾选，下轮继续修。

### 循环驱动（任选其一）

- **Codex 原生**：用 Codex 的 loop / automations，停止条件 = 上表「总门」全绿。
- **Ralph 式 while 循环**（每轮 fresh context，最稳）：
  ```bash
  i=0; until uv run pytest -q && uv run python scripts/check-verdict-path-imports.py; do
    i=$((i+1)); [ $i -gt 40 ] && { echo "迭代上限，停下求人类决策"; break; }
    codex exec --full-auto "读 CODEX_GOAL_BACKEND_V2.md 与 CODEX_PROGRESS.md；只做下一个未完成任务，先写测试再实现（红→绿），提交，更新 CODEX_PROGRESS.md。不要自评『完成』——由外层 gate 判定。"
  done
  ```
- **并行**：相互独立的 WS（如 A 与 G）用 `git worktree` 隔离并行，避免两个 agent 改同一文件造成脏状态。

### Loop Engineering 风险护栏（必须遵守）

1. **Verification gap**：done 永远由确定性门定义，**绝不接受 codex 自报**；早验勤验——每任务自带测试，不要攒到最后（compounding error 会滚雪球）。
2. **Comprehension debt**：每轮在 `CODEX_PROGRESS.md` 写一行人类可读 changelog；凡触碰 **verdict 路径 / 执行门 / 审批 / 签名** 的改动标 `⚠ human-review` 并暂停等人看 diff——别让循环顺畅地堆出没人懂的代码。
3. **Cognitive surrender**：循环顺畅 ≠ 正确；终态 DoD 必须人工过一遍 diff，尤其安全路径。「同一个 loop，两个人跑出相反结果——loop 不知道区别，你知道。」
4. **Token 成本**：设迭代上限（上例 40 轮）；卡住就停、在 `CODEX_PROGRESS.md` 的 `Blocked` 区标注求人类决策，别空转烧 token。

---

## 1. 背景与竞争驱动（为什么做这些改动）

同赛道（Bitget AI Hackathon S1 · Trading Infra）竞品深挖结论（详见 `/Volumes/Remi/hackathon/hackathons/bitget-ai-hackathon-s1-2026/`）：

- **TraceGuard**（最危险，5/5）：**真实实现了** fail-closed + 单次人工授权(burn-before-execute) + 真 prev-hash 链(`verifyChain` 可检测篡改) + 7100 行 tamper 测试。→ 我们的「hash-chain+fail-closed+人工审批」**概念护城河已不独家**。但它的 live 路径止于 `RunFailed`（**无一笔真实成交**），审批者只是字符串 `ops-desk`，且**没有对抗式崩溃回放层**。
- **AgentBench**（5/5）：已发 npm + 真 MCP + 浏览器 tamper demo + GitHub Action + leak-free 回测(next-bar fills/fees)。**但它宣传的 "hash-chained journal" 代码里根本不存在**（只有单点 content hash）。
- 其余可借鉴：**AI Trading DMV**（L0/L1/L2 准入分级 + agent 行为题：越权下单/跳确认/盲目重试）；**Sentinel Flight Recorder**（17 个 violation codes + block/modify/allow 三档 + merkle-sealed receipt）；**Agent BlackBox**（4 档裁决 ALLOW/REDUCE_SIZE/HUMAN_REVIEW/BLOCK + 自动缩仓）；**BitgetBench**（"回测的四个谎言" 叙事）；**TradeTrace**（一键 reproduce + "LLM 永不在安全决策路径"）；**SignalSieve**（输入侧信号 provenance）；**cmanueldecrypt**（诚实 limitations + docker 一键）。

**差异化策略（每条改动都服务于此）：**
1. **正面坐实 AgentBench 吹而未做的**：真·hash-chain（可独立验证 + 断链即 FAIL）+ leak-free replay（让我们的回测无法被一句「你的回测会泄露未来」打死）。
2. **绕开与 TraceGuard 的概念正面消耗**：我们独占「全链直达真实成交」+「审批绑定到已认证 principal **且** artifact digest」+「对抗式 crash-tape 回放」。
3. **借入分级（DMV）、违规码体系（Sentinel）、降档裁决（BlackBox/Sentinel）、分发与零密钥复核（AgentBench）**。

---

## 2. 北极星架构（目标态）

### 2.1 统一证据脊柱（核心改造）

**现状**：存在 3 条**互不引用**的哈希链（issuance-ledger、execution-ledger、release-audit-ledger），仅靠「`receipt_hash` 字符串值相等」关联（执行映射 §3）。

**目标**：每个下游工件携带**上游环节的哈希**，形成单一可走查的链：

```
edit_provenance(prompt_digest+diff_hash)         ← 已在 receipt_hash 内（receipt.py:147-152）
        ▼
Receipt(verdict) ──prev_receipt_hash──► issuance-ledger entry ──► signed checkpoint (Ed25519 + merkle_root)
        │ receipt_hash                                          │ checkpoint_hash
        ▼                                                       │
Approval(principal + artifact_digest + nonce, TTL, single-use) ──approval_hash──┐
        │  绑定 receipt_hash + package_hash + identity_lock_hash                  ▼
        ▼
ExecutionEvidence ──{receipt_hash + issuance_entry_hash + issuance_checkpoint_hash + approval_hash}──► execution-ledger entry(prev-hash)
        │ bitget_order_id + response_hash + clientOid=hash(receipt_hash,intent)
        ▼
ReleaseAttestation(Ed25519) 签 { bundle_hash, merkle_root([receipt, approval, execution]) }
```

判据：`redline verify-chain <release_dir>` 走完全链、重算每个哈希、用**公钥**验每个签名、验 merkle 包含证明，**任一字节篡改即非零退出并报精确 violation code**，**全程零密钥**。

### 2.2 设计原则（不可动摇）

1. **No proof, no verdict**：hash-only 仍只是 `unverified_no_verdict`，不能授权执行（保持 `BACKEND_COMPLETENESS.md` "Not A Verdict" 纪律）。
2. **Fail-closed**：verdict 路径与执行门的任何异常/缺证据都默认 BLOCK，绝不调用 Bitget（现状 `app.py:2127-2153` 已是，**不得削弱**）。
3. **LLM 永不在安全决策路径**：裁决是确定性的；LLM 只用于 spec 编译等非裁决环节（保持现状，pitch 可主打这点）。
4. **零密钥可验证**：所有对评委开放的验证只需**公开工件 + 公钥**，绝不需要 API key / 私钥。
5. **Schema 版本化**：改 schema 一律升版本号（如 `receipt.v3.2` → `v3.3`，`spec.v2.1` → `v2.2`），保留旧版读取兼容，新增字段优先 optional + 默认值，避免破坏既有 artifacts/demo。
6. **determinism**：verdict 路径禁 float/time/random/uuid/set/网络/LLM（见 WS-G）。
7. **诚实**：每个新机制都配**负向/篡改测试**；能力边界写进 `BACKEND_COMPLETENESS.md`；不在文案宣称代码没做的东西。

---

## 3. 硬约束（Codex 必须遵守，违反即回滚）

- **不得**让 verdict 路径（`proof_kernel.py`/`runner.py`/`verifier.py`/`probes/`/`engine_adapter/`）引入 net/LLM/native import 或非确定性来源；改动后 `scripts/check-verdict-path-imports.py` 与 `tests/test_backend_p0.py` 的纯度测试必须仍绿。
- **不得**把任何 `except` 写成「出错→放行」；执行门只能「出错→BLOCK」。
- **不得**把私钥/凭证写入任何 artifact、日志或 evidence（沿用 `_redact_secrets`）。
- **不得**降低现有 fail-closed/mainnet 双控（`bitget_execution.py:364-371`）。
- **每个 workstream 必须自带测试且全套 `uv run pytest` 通过**；新增负向测试是验收的一部分，不是可选项。
- 改动**最小化**、复用现有 helper（`canonical.hash_obj`、`trust.sign_checkpoint`、`load_*_ledger` 等），不造平行机制。

---

## 4. 工作流（按依赖顺序；每个 WS 可独立提交 + 测试）

> 依赖：WS-A、WS-G 可并行先做；WS-B 依赖 WS-A 的 schema 升版；WS-C/D/E 依赖 WS-B 的链字段；WS-F 依赖 WS-B/C/D/E 全部完成。

---

### WS-A：Leak-free replay 引擎 + tape provenance 〔对标 AgentBench / BitgetBench 的「回测四谎言」〕

**目标**：让我们的确定性回放在会计层 **无 look-ahead、计费用、计滑点、next-bar 成交**，并把这些做成**可证明的 proof 字段**，从根上免疫「你的回测会泄露未来」攻击。

**现状（最大空白）**：`engine_adapter/deterministic.py::_build_trace`（:163-221）用**当根 bar 的 close 对当根收益计 NAV**（`nav *= 1 + position*ret`，:185-189），**无 next-bar fill、无 fees、无 slippage**；schema 无 `fee/slippage/fill` 字段；probe 仅 `max_drawdown/no_entry_when/trade_budget`（`models.py:77-81`）。look-ahead 仅靠 sandbox 防「偷看未来 bar 文件」，**不防会计层 look-ahead**。

**改动**：
1. `engine_adapter/deterministic.py::_build_trace`：信号在 bar `i`（close）计算、**在 bar `i+1` open 成交**（next-bar fill，结构性无前视）；引入 `fee_bps`（taker/maker）、`slippage_bps`（按 size 缩放、**方向恒不利**）、可选 funding。NAV/drawdown 基于成交后持仓。
2. `models.py`：`Bar` 增 `open`（若缺）；`Scenario`/`ReplayPoint` 增成交价、费用、滑点记录；`Suite/Scenario` 增 `source_file_hash`（tape provenance，借 SignalSieve）。
3. `schemas/spec.v2.2.schema.json`（升版）+ `spec_compiler.py`：新增 `fee_bps/slippage_bps/fill_model=next_bar_open` 参数，默认值要保守且确定。
4. 新增 **leak-free proof 字段**：receipt/proof 内记录 `fill_model`、`lookahead_guard=structural_next_bar`、`fees_modeled=true`，使其成为可被 `verify-proof` 复核的断言。
5. 新增 probe 类型（借 DMV/BlackBox 行为题）：`unauthorized_order`（策略尝试越权品种/杠杆）、`skip_confirm`（跳过应有确认）、`blind_retry`（失败后盲目重试）—— 作为 verdict-bearing 或 advisory probe。

**验收**：
- 同一 tape + 同一策略，跑两次字节级一致（determinism 不破）。
- 存在测试：构造一个「利用同根 close 才能盈利」的策略，旧模型 PASS、**新 next-bar 模型必须 WITHHELD/REDUCE**（证明 look-ahead 被消除）。
- `verify-proof` 能独立复核 leak-free 字段；篡改 `fee_bps` 或成交价 → 验证 FAIL。

**测试**（加到 `tests/test_backend_p0.py`）：`test_next_bar_fill_kills_lookahead_strategy`、`test_fees_slippage_reduce_pnl_deterministically`、`test_tape_source_hash_tamper_rejects`、新 probe 各 1 正 1 负。

---

### WS-B：统一可验证链（receipt prev-hash → execution 链接 → approval 链接 → merkle → attestation）〔对标 TraceGuard 真链 + 坐实 AgentBench 假链〕

**目标**：把 3 条独立链焊成一条密码学脊柱（见 §2.1），并加 merkle 聚合（借 Sentinel）。

**现状**：
- receipt 间无 receipt 级 prev-hash，因果靠 `baseline.baseline_receipt_hash` 间接表达（verdict 映射 §3）；`anchor_kind` 默认 `local-artifact`。
- execution-ledger 与 issuance-ledger 互不引用（执行映射 §3，`bitget_execution.py:524-536` 自带独立 genesis）。
- 无任何 `merkle` 实现（全仓零命中）。
- attestation 只签 release bundle，间接覆盖 execution evidence（执行映射 §4）。

**改动**：
1. `models.py::Receipt` 增 `prev_receipt_hash`（同主体上一份 receipt 的 hash，genesis 为 `sha256:genesis`）；`receipt.py::issue_receipt`/`compute_receipt_hash` 纳入它。保持向后兼容（旧 receipt 无此字段时按 genesis 处理）。
2. `models.py::ExecutionLedgerEntry`/`ExecutionEvidence` 增 `issuance_ledger_entry_hash`、`issuance_checkpoint_hash`、`approval_hash`；`sponsor/bitget_execution.py:524-557` 写入时填充并纳入 `entry_hash`/`artifact_hash`。
3. `service/app.py:2180-2229`（`_place_verified_bitget_demo_order`）：把 approval 的 `approval_hash`（见 WS-C）写进 execution evidence。
4. 新增 `src/redline/merkle.py`：标准二叉 merkle（确定性、Decimal 无关，纯 sha256 over canonical bytes），提供 `merkle_root(leaves)` + `merkle_proof(leaves, i)` + `verify_inclusion`。
5. `receipt.py::create_ledger_checkpoint`（:222-245）增 `merkle_root`（over `subject_receipt_hashes`）；`schemas/ledger-checkpoint.v1` → 升版加字段。
6. `attestation.py::_attestation_payload`（:152-153）：被签 payload 纳入 `merkle_root([receipt_hash, approval_hash, execution_evidence_hash])`，使 attestation **直接覆盖**单条执行证据，而非仅靠 bundle 包含。

**验收**：
- 一条完整 release 跑完后，存在可程序化走查的链：`prev_receipt_hash` 连续、execution entry 引用的 issuance entry/checkpoint 哈希真实存在且匹配、attestation 的 merkle root 包含 execution evidence。
- 篡改链中任一环（receipt/approval/execution/checkpoint）→ 走查 FAIL 并报出**是哪一环**。

**测试**：`test_receipt_prev_hash_chain_continuous`、`test_execution_evidence_links_to_issuance_entry`、`test_merkle_inclusion_of_execution_evidence`、`test_attestation_covers_execution_evidence`、`test_chain_break_pinpoints_broken_link`（逐环篡改各一例）。

---

### WS-C：审批加固 〔正面击败 TraceGuard 的 action_digest，并补 single-use/TTL/four-eyes/SKIP≠PASS〕

**目标**：审批绑定到 **已认证 principal + 精确 artifact digest**，**单次消费 + TTL**，**真四眼**，且 gate 不可 SKIP 当 PASS。

**现状**（release 映射 §2/§3/§4）：
- approval 已绑认证 principal（`app.py:710-728`，强）。
- 但 `evidence_fingerprint`（`release.py:109-121`）**不含 `package_hash`/`identity_lock_hash`** → 绑的是 `version_id` 字符串而非候选内容哈希（**命门**）。
- **无 single-use / consumed / nonce / expires_at**（grep 0 命中）；showcase 可凭同一 approval 反复下单。
- four-eyes 弱：`demo_mode=True` 绕过自审（`app.py:714`）；无审批者角色门槛；`created_by` 是请求自报字段。
- SKIP≠PASS 部分缺：`require_demo_execution`/`require_human_approval` 是死字段；`BLOCKED_MISSING_EVIDENCE` 永不触发。

**改动**：
1. `service/release.py:109`（`evidence_fingerprint`）：纳入 `strategy_version.package_hash` + `identity_lock_hash`；`app.py:719` 传入 strategy_version。
2. approval 模型（`service/models.py:207` 区）增 `nonce`、`expires_at`、`consumed_at`；store 加列（`store.py:125` + `postgres_store.py:127` + 一条 `service/migrations.py` 迁移）。
3. 执行/showcase 入口（`app.py:807`、`:930`）：改为**原子「校验 + 消费」**——已 consumed 或已过期 → BLOCK（新 violation code `APPROVAL_CONSUMED`/`APPROVAL_EXPIRED`）。showcase 多次下单需显式策略（要么每次需新 approval，要么 release 级「showcase 授权」与「单次执行授权」分离并各自记账）。
4. `app.py:714`（approve 入口）：要求 `principal.role ∈ {reviewer, release_manager}`；**删除 `and not payload.demo_mode` 自审豁免**；`created_by`（`app.py:455`）改存**认证主体快照**而非请求字段。
5. SKIP≠PASS：把「进入 `REVIEW_REQUIRED`/`APPROVED` 的前置证据齐备性」做成 `service/transitions.py:83`(`transition_release`) 的 per-target guard；`app.py:1941`(`_approval_block_reason`) 增读 `require_demo_execution`（断言 `execution_evidence` 存在）与 `require_human_approval`；缺失落 `BLOCKED_MISSING_EVIDENCE` 而非默默 `EVIDENCE_COLLECTING`。
6. `approval_hash = hash_obj(approval 去签名/易变字段)`，供 WS-B 写入执行链。

**验收**：
- approval 绑定 artifact digest：候选内容变更后旧 approval 失效（已有 `APPROVAL_EVIDENCE_CHANGED`），且**即使 version_id 不变、package 内容变也失效**。
- 同一 approval 第二次执行 → BLOCK（single-use）。
- 过期 approval → BLOCK。
- author 无法批自己的 release（含 `demo_mode` 路径）；非 reviewer/release_manager 角色无法审批。
- 缺 demo 执行而 policy 要求时 → `BLOCKED_MISSING_EVIDENCE`。

**测试**：`test_approval_binds_package_hash_not_just_version_id`、`test_approval_single_use_blocks_replay`、`test_approval_ttl_expiry_blocks`、`test_self_approval_forbidden_even_in_demo_mode`、`test_non_reviewer_role_cannot_approve`、`test_require_demo_execution_enforced`。

---

### WS-D：分级裁决 + 分级发布许可（L0/L1/L2）+ REDUCE_SIZE 中间档 〔借 DMV + Agent BlackBox + Sentinel〕

**目标**：把二元 PASS/WITHHELD 升级为 **ALLOW / REDUCE_SIZE(modify) / HUMAN_REVIEW / BLOCK** 四档；发布侧给 **L0/L1/L2 许可分级**。

**现状**：verdict 实质二元（`proof_kernel.decide` :71-138，只出 PASS/WITHHELD）；release 无 tier（release 映射 §8，`RELEASED_LIVE_GATED` 是 dead state）。

**改动**：
1. `proof_kernel.py::decide`（唯一决策点）：引入 `VerdictTier`（ALLOW/REDUCE_SIZE/HUMAN_REVIEW/BLOCK）。REDUCE_SIZE 携带 `adjusted_size_cap`（如 drawdown 超阈但可缩仓达标时）。`models.py::Status`/`ResultInfo.status`（:660 写死的 `Literal["pass","withheld"]`）放开为含新档；`schemas/receipt.v3.x` 升版。
2. `service`：新增 `compute_release_tier(release, strategy_version)`（`app.py:1941` 同区）。判级输入：run-pass + sim 完备度 + risk headroom + 是否真跑过 demo-exec。**L0**=sim-only（未真执行）；**L1**=已 paptrading demo 执行 + 全证据链完整；**L2**=live-gated（需 mainnet 双控 + 额外 reviewer）。tier 存 `ReleaseCandidateResponse`（`models.py:192`）+ store 列 + 写入 decision-record（`release.py:158`）。
3. `RELEASED_LIVE_GATED` 仅在 **L2 + 双控** 下可达（`transitions.py:68` 落地，当前 dead）。
4. `service/release.py:128`(`risk_policy_breach`) 改为返回结构化 `{decision: allow|reduce|block, adjusted_size?, reason}`；执行入口（`app.py:811`/`:952`）消费 reduce 决策（按 `adjusted_size` 下单），把「降档放行」做成真实路径而非二元。

**验收**：
- 一个「裸放会超 drawdown、但缩仓 50% 达标」的候选 → 裁决 REDUCE_SIZE 且执行用缩后 size 真实下单。
- 仅 sim 未执行的 release → L0；执行成功 → L1；L2 路径受双控保护。
- tier 写入 receipt/decision-record，可被 verify 复核。

**测试**：`test_reduce_size_tier_caps_position`、`test_release_tier_l0_l1_l2_transitions`、`test_live_gated_requires_l2_and_double_control`、`test_risk_policy_reduce_decision_executes_adjusted_size`。

---

### WS-E：结构化 violation 码体系 + 严重度 + 目录 〔借 Sentinel 的 17 codes〕

**目标**：把过载的 `RECEIPT_MISMATCH` 拆成**精确到环节**的码，加 severity/可恢复性，生成文档目录，提升评委可读性与诊断分辨率。

**现状**：`models.py::ReasonCode`（:28-53）25 码，单一枚举源（好），但 `RECEIPT_MISMATCH` 被 receipt/proof/ledger/checkpoint/report 全部复用（诊断分辨率低）；无 severity；无独立文档。

**改动**：
1. `models.py::ReasonCode`：新增 `PROOF_HASH_MISMATCH`、`LEDGER_CHAIN_BROKEN`、`CHECKPOINT_MISMATCH`、`EXECUTION_LEDGER_BROKEN`、`MERKLE_INCLUSION_FAILED`、`APPROVAL_CONSUMED`、`APPROVAL_EXPIRED`、`CHAIN_LINK_MISMATCH` 等；`RECEIPT_MISMATCH` 收窄为「receipt 自身摘要不符」。
2. `verifier.py`（`_receipt_binding_error`/`_ledger_error`/`_ledger_checkpoint_error`）按环节精确归码。
3. 同步 3 个内联 schema（receipt.v3.x / proof-verification.v1 / verification-result.v1）的 enum + `cli.py::EXIT_BY_REASON` 退出码映射。
4. 给每个码加 `severity`(blocking/advisory) 与 `recoverable`(bool) 元数据（可用一个 `REASON_META: dict[ReasonCode, ...]`）。
5. 新增脚本 `scripts/gen-violation-catalog.py` 生成 `docs/VIOLATION_CODES.md`（码 → 含义/严重度/触发处），并加一个测试断言「枚举与文档同步」。

**验收**：逐环节篡改命中**不同**的码（不再都归 RECEIPT_MISMATCH）；`docs/VIOLATION_CODES.md` 与枚举一致（测试守护）。

**测试**：`test_proof_tamper_gets_proof_specific_code`、`test_ledger_break_vs_checkpoint_mismatch_distinct_codes`、`test_violation_catalog_in_sync`。

---

### WS-F：零密钥评委复核工具链 + tamper demo + GitHub Action + golden 测试 〔对标/超越 AgentBench 分发与可玩性〕

**目标**：把「评委零密钥独立复核 + 改一字节变红」做成一等公民，分发体验对标 AgentBench 的 npx + Action。

**现状**：`verify-release-bundle/-attestation/-ledger-attestation` 已零密钥（执行映射 §8），但**无 `verify-chain` 全链命令、无 `verify-execution-evidence` 单订单命令、无 GitHub Action、无脚本化 tamper demo**。

**改动**：
1. `cli.py` 新增 `@app.command("verify-chain")`：输入一个 release 目录/bundle，**走完 §2.1 全链**（prev_receipt_hash → issuance entry/checkpoint → approval → execution → attestation + merkle 包含），逐环验签验哈希，输出 JSON envelope（每环 pass/fail + violation code），**任一失败非零退出**。零密钥（只用公钥 + 公开工件）。
2. `cli.py` 新增 `@app.command("verify-execution-evidence")`：包装 `load_execution_evidence`/`load_execution_ledger`（`bitget_execution.py:418/585`），独立验证单条订单证据 + 链接，零密钥。
3. `scripts/tamper-demo.sh`：复制一份通过的 evidence → 翻转一个字节 → 跑 `verify-chain` → 展示**精确 violation code + 非零退出**（评委「改个数→变红」现场演示）。
4. `.github/workflows/verify-evidence.yml`：在 CI 跑 `verify-chain` 校验仓库内 committed 的 demo evidence；断链/篡改即 **fail the build**（对标 AgentBench Action）。同一 workflow 跑 `scripts/check-verdict-path-imports.py`（见 WS-G）。
5. **golden 测试**（借 TraceGuard）：断言评委 evidence HTML / receipt 由 `render.py`/`receipt.py` **代码即时再生**、与提交副本字节一致，堵死「静态文件冒充」。
6. 更新 `README.md` + `BACKEND_COMPLETENESS.md`：加「评委 60 秒零密钥复核」三条命令 + tamper demo 入口；诚实标注能力边界（借 cmanueldecrypt 的 limitations 段）。

**验收**：
- 全新 checkout、无任何密钥，`redline verify-chain artifacts/release-demo/current/...` 通过且打印逐环结果。
- `scripts/tamper-demo.sh` 翻转一个字节后必然非零退出 + 报精确码。
- CI workflow 在篡改 evidence 时 fail。

**测试**：`test_verify_chain_happy_path_zero_secret`、`test_verify_chain_detects_each_tampered_link`、`test_verify_execution_evidence_cli`、`test_evidence_html_golden_regenerated`。

---

### WS-G：determinism 静态门加固 + CI 〔守护护城河的根〕

**目标**：把 verdict 路径纯度从「运行期 tripwire + sandbox」前移为**静态可门控 + CI 强制**，并覆盖 float/time/random/uuid/set。

**现状**：`scripts/check-verdict-path-imports.py` 只禁 net/native/LLM import（`CHECK_PATHS` 仅 `proof_kernel/verifier/probes`），**不禁 float/time/random/uuid/set**；CI 是否门控**待核实**（未确认 `.github/`）。float 纯度靠 `canonical.normalize` 抛错、entropy 禁用靠 sandbox。

**改动**：
1. `scripts/check-verdict-path-imports.py`：`FORBIDDEN_MODULES` 增 `time/random/uuid/secrets/datetime`；新增对 `float(`/`set(`/`frozenset(`/`{...}` set 字面量的 AST 静态检测（在 verdict 路径文件内）；`CHECK_PATHS` 扩到 `runner.py`、`receipt.py`、`engine_adapter/deterministic.py`、`proof_kernel.py`、`tripwire.py`。
2. 确认/新增 CI：`.github/workflows/verify-evidence.yml`（或独立 `purity.yml`）运行该脚本 + 纯度相关 pytest，作为必过 gate。
3. 给 `tests/test_backend_p0.py` 的 `test_verdict_path_import_gate_passes_current_repo`（:2281）补充：断言新禁则确实拦截（构造一个含 `import random` 的临时 verdict 文件应被拒）。

**验收**：脚本在 verdict 路径引入 `import random`/`float(...)`/`set(...)` 时退出非零；CI 实际运行该 gate。

**测试**：`test_purity_gate_bans_entropy_and_float_set`。

---

## 5. 总验收（Definition of Done）

1. `uv run pytest`（含全部新增正/负测试）**全绿**。
2. `scripts/check-verdict-path-imports.py` 通过（含新禁则）。
3. `scripts/release-demo.sh` 端到端跑通：建版本 → release → 绑 PASS run（**leak-free 模型**）→ 导 sim → 绑 risk → **四眼审批（principal+digest+single-use）** → **真实 paptrading demo 下单** → 生成 bundle + attestation → tier 判级。
4. `redline verify-chain <release_dir>` **零密钥**走完全链通过；`scripts/tamper-demo.sh` 翻字节后非零退出 + 精确码。
5. `.github/workflows/verify-evidence.yml` 在篡改 evidence 时 fail。
6. `BACKEND_COMPLETENESS.md`、`README.md`、`docs/VIOLATION_CODES.md`、`SERVICE_API.md`/`schemas/service-openapi.json` 与新行为一致（schema 已升版，OpenAI/JSON schema 重新导出）。
7. 所有 schema 改动均升版本号且保留旧版读取兼容；既有 `artifacts/demo/*` 仍可被 verify（或提供迁移并说明）。

## 6. 明确不做（Out of Scope，诚实边界）

- **前端**（本轮不碰；evidence HTML/judge console 仅在 golden 测试范围内保证可再生）。
- **真实 mainnet 下单**（保持双控阻断默认）。
- **新的真实回测数据源/外部行情拉取进 verdict 路径**（verdict 必须离线确定性；行情只在受控 tape 内）。
- 不引入新的重型依赖；merkle/签名复用 `hashlib`/`cryptography`。

## 7. 验证命令速查

```bash
uv run pytest -q
uv run python scripts/check-verdict-path-imports.py
scripts/release-demo.sh
uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json
uv run redline verify-execution-evidence artifacts/release-demo/current/service/releases/release-demo-good --json
scripts/tamper-demo.sh    # 期望：非零退出 + 精确 violation code
uv run python scripts/export-service-openapi.py   # 重新导出 OpenAPI
```

## 8. 给 Codex 的执行提示

- **按 Loop Engineering 跑（见 0.5）**：这是一个**循环**，不是一次性任务。每轮：读 `CODEX_PROGRESS.md` → 挑一个未完成任务 → 红→绿 → 提交 → 跑该任务确定性门 → 回填状态 + changelog。**done 由确定性门的退出码定义，不由你自评。**
- **先读后改**：开工前用 `rg` 复核每个 file:line 锚点（代码可能已演进），以实际为准。
- **小步提交**：每个 WS 一组 commit，先加测试再改实现（红→绿），保留真实开发史（评委看重，且这是我们相对「单 commit 灌库」竞品的工程可信度优势）。
- **每步自检**：改 verdict 路径后立即跑纯度 gate + 纯度测试；改执行/审批后立即跑 release-demo 烟雾。
- **遇到 schema 破坏性变更**：升版本 + 写迁移 + 更新既有 demo artifacts，不要静默破坏。
- **不确定就标 TODO 并写测试占位**，不要假装实现（沿用本仓 honesty-first 基调）。
- 优先级：**WS-A（leak-free）+ WS-B（统一链）+ WS-F（零密钥验证 + tamper demo）** 是对评委冲击最大、对标 AgentBench/TraceGuard 最直接的三块，若时间有限先交付这三块的最小可验证闭环。
```
