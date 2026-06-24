# CODEX GOAL — Playbook Redline 后端 v3：把「不建议做」升级为「受控建议做」

> 生成日期：2026-06-24  
> 范围：后端、服务接口、证据链、发布控制面、交易执行安全、评委实时演示支撑。  
> 目的：把 v2 中出于时间和风险被列为 Out of Scope / 不建议直接做的内容，改写成可分阶段实施、可验证、fail-closed 的后端能力。  
> 不替代 `CODEX_GOAL_BACKEND_V2.md`；v2 是当前证据链主线，v3 是下一轮生产化与展示增强主线。

---

## 0. 一句话使命

把 Playbook Redline 从「可验证的 hackathon 后端」推进到「生产级交易发布控制后端」：

> 评委可以实时触发 demo-only 交易演示；策略作者可以导入模拟盘与实盘证据；release manager 可以通过真实身份、审批、迁移、幂等、状态机、交易所预检、订单对账和可验证证据链，把 AI 策略发布推进到明确分级的 release readiness，而不是只看静态回放。

这轮的核心变化不是做一个前端，而是把以前不建议做的高风险方向都改成**后端可控、默认安全、可测试、可回滚、可审计**的建议做事项。

---

## 1. 重要前提

1. **不破坏 v2 已有红线**：`run_redline -> decide` 仍是唯一 verdict 路径。任何展示、实时按钮、导入、publish preflight、AI 辅助说明都不得创造 verdict。
2. **demo-only 默认**：Bitget 下单默认只允许模拟盘，必须带 `paptrading: 1` 语义和 evidence 标记。主网仍需双控，不允许因为“展示需要”放松。
3. **后端优先**：不做 SPA/React/图表库；但是要提供未来任何前端都能可靠调用的 API、job、event stream、HTML evidence、OpenAPI contract。
4. **建议做不等于无约束做**：每个原先不建议做的方向都必须有开关、权限、审计、幂等、测试、负向路径和文档边界。
5. **评委可操作**：目标不是堆功能，而是让评委在 10 秒内看到“按钮触发真实 Bitget demo order、订单被 Redline verdict 授权、证据链可零密钥验证、篡改即失败”。

---

## 2. 把「不建议做」转成「建议做」的映射

| 原先不建议 / Out of Scope | v3 建议做法 | 安全边界 |
|---|---|---|
| 前端 / SPA / React | 做后端实时控制面：job API、SSE/NDJSON event stream、server-rendered HTML evidence、OpenAPI contract | 不引入前端框架；HTML 只读；按钮动作必须走 token/RBAC/job/idempotency |
| 实时刷新 / 实时演示 | 做 durable job + event ledger + judge-trigger endpoint，支持评委点击后实时观察 demo order 过程 | 只允许 demo order；每次执行消耗独立 approval 或 showcase approval；重复点击不重复下单 |
| Playbook upload/publish | 做 Playbook import、publish preflight、sponsor adapter dry-run、final publish 双控状态机 | 不宣称正式 Bitget Playbook 发布；final-publish 默认禁用 |
| 不改鉴权模型 | 做真实 auth/RBAC 生产补齐：principal、role、scope、session/OAuth、approval 绑定 authenticated user | legacy service token 仅保留 demo/internal；审批不能信请求体 reviewer_id |
| 不引入新依赖 | 做依赖准入机制：需要时允许小而必要的后端依赖，但必须 ADR、license/CVE 检查、lockfile、替代方案说明 | verdict 路径禁止新增网络/LLM/native/非确定性依赖 |
| 不拉外部行情进 verdict | 做外部数据导入管道：GetAgent Studio/CSV/JSON 原始文件 hash + normalized summary + provenance | verdict 只消费已固定 tape/summary，不在判决时联网 |
| 不做 mainnet | 做 mainnet readiness runway：shadow mode、dry-run、双控、kill switch、readback verification | 默认不下主网；测试/demo 不需要主网密钥 |
| 静态回放展示 | 做 live showcase 多笔 demo 下单、订单对账、status evidence、失败恢复演示 | 任何失败都显示 blocked/reconciliation_required，不伪造成成功 |

---

## 3. 北极星目标态

### 3.1 生产级 release control plane

目标后端应该能表达完整 release 生命周期：

```text
strategy_imported
  -> simulation_evidence_imported
  -> redline_replayed
  -> risk_preflight_passed
  -> human_review_required
  -> approved
  -> demo_execution_ready
  -> demo_executed_and_reconciled
  -> release_ready_l1
  -> publish_preflight_ready
  -> live_gated_l2
```

所有转换都通过一个 transition table，任何 endpoint 都不能绕过状态机。

### 3.2 评委实时演示后端

评委点击按钮时，后端应该做的是：

1. 验证 token/session principal 与 scope。
2. 验证 release 当前状态、risk policy、approval、freeze switch。
3. 创建 job，写入 job ledger。
4. 通过同一 release execution gate 触发 Bitget demo order。
5. 下单后按 `clientOid` 查询订单状态，写 `order-status-evidence.json`。
6. event stream 实时吐出每一步：accepted、verified、preflight_passed、order_placed、reconciled、evidence_written、verify_chain_passed。
7. 生成或更新 evidence HTML 和 JSON bundle。
8. 如果任何一步失败，job 以 blocked/failed/reconciliation_required 结束，且不得重复下单。

### 3.3 证据完整性

每个新能力都必须写入公开可验证证据：

- import evidence：原始文件 hash、解析器版本、normalized summary hash。
- approval evidence：authenticated principal、role、scope、artifact digest、nonce、expires/consumed。
- execution evidence：request intent hash、clientOid、Bitget order id、order status readback、response hash。
- event evidence：job event hash-chain。
- release decision record：tier、reason、risk headroom、simulation coverage、execution reconciliation status。

---

## 4. 执行模型

本目标按 Loop Engineering 执行。每轮只做一个任务：

1. 读 `CODEX_GOAL_BACKEND_V3_RECOMMENDED.md`。
2. 新建或维护 `CODEX_PROGRESS_BACKEND_V3.md`。
3. 找到第一个未完成任务。
4. 先写测试或 contract。
5. 实现最小可用路径。
6. 跑该任务 gate。
7. 回填 progress：PASS/FAIL、命令、简短 changelog、是否 human-review。

触碰以下路径必须标 `human-review`：

- verdict/proof kernel
- execution gate
- approval/auth/RBAC
- order placement/reconciliation
- signing/attestation/hash-chain
- final publish/mainnet controls

---

## 5. 工作流

### WS-H：Backend live judge control plane

**目标**：把“评委实时点击按钮演示”做成后端能力，而不是前端假按钮。

**建议做**：

1. 新增或加固 judge job API：
   - `POST /v1/judge/releases/{release_id}/actions/demo-order`
   - `GET /v1/judge/jobs/{job_id}`
   - `GET /v1/judge/jobs/{job_id}/events`
   - `GET /v1/judge/jobs/{job_id}/events.ndjson`
2. job 必须 durable：进 SQLite/Postgres，重启后能恢复 queued/running 状态。
3. 每个 job event 写 hash-chain，event read 会校验链。
4. 支持多笔 showcase demo orders：
   - `scenario=baseline_pass`
   - `scenario=reduce_size`
   - `scenario=withheld_blocked`
   - `scenario=reconciliation_recovered`
5. 每笔订单都有独立 `clientOid`、attempt id、approval/authorization hash。
6. 同一个 `Idempotency-Key` 重试返回同一个 job；不同 body 返回 409。
7. 返回结构必须适合未来按钮直接使用：`accepted|running|blocked|succeeded|failed|reconciliation_required`。

**不得做**：

- 不用前端框架。
- 不在 HTML 内嵌密钥。
- 不让 judge endpoint 绕过 release execution gate。
- 不因为重复点击产生重复订单。

**测试**：

```bash
uv run --extra dev pytest -q -k "judge_job or event_chain or demo_showcase or idempotency"
```

**验收**：

- 连点两次相同 action，不重复下单。
- job event 链篡改后读取失败。
- bad release 返回 blocked，并明确 “Bitget not called”。
- good release 至少能生成 3 笔不同参数/场景的 demo-only evidence。

---

### WS-I：Playbook import / publish preflight / final publish readiness

**目标**：把以前“不碰 Playbook upload/publish”改成建议做的后端 preflight 能力，但不假装已经接入 Bitget 正式 Playbook 发布。

**建议做**：

1. Playbook package import：
   - raw upload
   - canonical package hash
   - strategy identity lock
   - source provenance
   - schema validation
2. Publish preflight：
   - Redline PASS 或 REDUCE_SIZE 路径
   - release evidence complete
   - demo execution reconciled
   - human approval valid and consumed correctly
   - freeze switch off
3. Sponsor adapter dry-run：
   - 生成 sponsor request preview
   - 不调用正式 publish
   - 写 sponsor-preflight-evidence.json
4. Final publish gate：
   - 默认 disabled
   - 需要 `REDLINE_ALLOW_FINAL_PUBLISH=1`
   - 需要 `confirm_final_publish=true`
   - 需要 release tier L2
   - 需要 release_manager + second reviewer
   - 需要 signed ledger checkpoint
5. Contract-faithful docs：
   - 明确 “非 Bitget Playbook 正式发布”
   - 明确 sponsor adapter 当前做到哪一步
   - 明确如何接入未来官方 Playbook API

**测试**：

```bash
uv run --extra dev pytest -q -k "playbook_import or publish_preflight or final_publish_gate or sponsor_adapter"
```

**验收**：

- upload 同一包返回同一 hash。
- 改一个字节 package hash 改变，旧 approval 失效。
- final publish 缺任意双控条件都 blocked。
- dry-run evidence 可进 release evidence bundle 并被 verify-chain 覆盖。

---

### WS-J：Mainnet readiness runway

**目标**：不是马上下主网，而是把“未来主网发布需要什么后端控制”做成可测试 runway。

**建议做**：

1. Shadow mode：
   - 生成 mainnet-equivalent intent
   - 不发送 order request
   - 写 shadow-execution-evidence.json
2. Read-only exchange preflight：
   - account mode
   - symbol exists
   - min size/min notional
   - precision
   - leverage/margin mode
   - current position exposure
3. Dual-control live gate：
   - env allow flag
   - request confirm flag
   - L2 release tier
   - release_manager approval
   - second reviewer approval
   - explicit max notional cap
4. Kill switch：
   - global execution freeze
   - release freeze
   - symbol-level freeze
   - account-level freeze
5. Post-action reconciliation mandatory：
   - no reconciled status means release cannot progress.

**测试**：

```bash
uv run --extra dev pytest -q -k "mainnet_readiness or shadow_mode or double_control or kill_switch"
```

**验收**：

- 默认配置下所有 mainnet action 都 blocked。
- shadow mode 生成完整 evidence，但不会调用 Bitget order endpoint。
- 开启一半控制仍 blocked。
- kill switch 在任何状态下优先 blocked。

---

### WS-K：GetAgent Studio / simulation evidence import

**目标**：把“外部数据不进 verdict 路径”改成建议做的受控导入：原始数据可以进 evidence，判决只消费固定 hash 与 normalized summary。

**建议做**：

1. 支持上传 CSV/JSON/ZIP：
   - raw file atomic write
   - source_file_hash
   - parser name/version
   - normalized summary hash
2. GetAgent Studio format detector：
   - 识别字段映射
   - 生成 normalized trades/equity/risk summary
   - 对缺字段 fail closed
3. Evidence import API：
   - `POST /v1/release-candidates/{release_id}/simulation-files`
   - `GET /v1/release-candidates/{release_id}/simulation-evidence`
4. 数据安全：
   - 限制文件大小
   - 拒绝 symlink/hardlink
   - MIME/扩展名只做辅助，实际按内容解析
   - 解析失败写 blocked evidence，不静默忽略
5. Bundle 覆盖：
   - release evidence bundle 同时包含 raw hash 与 normalized summary hash。

**测试**：

```bash
uv run --extra dev pytest -q -k "simulation_file_import or getagent or source_file_hash or normalized_summary"
```

**验收**：

- 导入 GetAgent Studio 样例后生成 deterministic normalized summary。
- 篡改 raw 文件后 bundle verify 失败。
- 缺 simulation evidence 的 release 不可进入 release_ready。

---

### WS-L：Production auth / RBAC / audit principal

**目标**：把“service token 适合 demo”升级成生产身份体系。

**建议做**：

1. Auth principal store：
   - user id
   - provider
   - login
   - display name
   - email hash
   - role
   - disabled_at
2. Role model：
   - author
   - reviewer
   - release_manager
   - admin
3. Token scope：
   - read-only
   - release-write
   - execute-demo
   - publish-preflight
   - admin
4. Approval：
   - reviewer_id 永远来自 authenticated principal
   - 请求体不能覆盖 reviewer identity
   - self approval 永远禁止，包括 demo mode
5. Audit ledger：
   - 每个 state transition 记录 authenticated principal
   - 每个 evidence download/attestation/job action 记录 principal fingerprint
6. Session hardening：
   - HMAC session secret production required
   - cookie flags
   - CSRF for browser-origin unsafe methods if cookie auth is enabled
7. Admin endpoint：
   - list principals
   - rotate token
   - disable user
   - audit role changes

**测试**：

```bash
uv run --extra dev pytest -q -k "auth_principal or rbac or self_approval or scope or audit_principal"
```

**验收**：

- author 不能审批自己的 release。
- reviewer 没有 execute-demo scope 不能下 demo order。
- service token 与 session principal 均能落审计，但身份来源清楚。
- role 变更写入 audit ledger。

---

### WS-M：Versioned migrations / database durability

**目标**：把 idempotent 建表升级为生产迁移系统和数据耐久策略。

**建议做**：

1. `schema_migrations`：
   - version
   - checksum
   - applied_at
   - applied_by
2. SQL migrations：
   - SQLite
   - Postgres
   - forward-only
   - checksum locked
3. CLI：
   - `redline service-migrations status`
   - `redline service-migrations apply`
   - `redline service-migrations dry-run`
   - `redline service-migrations verify`
4. Startup check：
   - missing migrations fail readiness
   - never auto-destruct data
5. Postgres CI:
   - migration from empty DB
   - migration from v2 snapshot
   - downgrade unsupported but detected clearly
6. Backup/retention：
   - release evidence immutable by default
   - cleanup never deletes release_ready evidence
   - backup manifest hash

**测试**：

```bash
uv run --extra dev pytest -q -k "migration or schema_migrations or retention or backup_manifest"
```

**验收**：

- 修改 migration 文件 checksum 后 verify 失败。
- 旧 DB 启动时能 apply 到当前版本。
- 缺 migration 的 service readiness 返回 unhealthy。
- cleanup 不会删除 release evidence bundle。

---

### WS-N：Exchange preflight / order reconciliation / duplicate prevention

**目标**：把 demo order 从“已下单写 evidence”升级成交易系统标准闭环：预检、下单、超时恢复、订单查询、状态归档。

**建议做**：

1. Exchange preflight：
   - demo account balance
   - symbol exists
   - productType matches
   - marginCoin matches
   - min size/min notional/precision
   - leverage/margin mode
   - current exposure
2. Order placement：
   - deterministic clientOid
   - idempotency ledger
   - request hash
   - response hash
3. Timeout recovery：
   - 如果下单 HTTP timeout 但 clientOid 已生成，必须先用 clientOid/order query 恢复状态
   - 不允许直接重发导致重复下单
4. Order status evidence：
   - placed
   - partially_filled
   - filled
   - cancelled
   - rejected
   - unknown_reconciliation_required
5. Reconciliation API：
   - `POST /v1/executions/{execution_id}/reconcile`
   - `GET /v1/executions/{execution_id}/order-status`
6. Failure semantics：
   - preflight fail：Bitget order endpoint not called
   - placement uncertain：reconciliation_required
   - rejected/cancelled：not release_ready

**测试**：

```bash
uv run --extra dev pytest -q -k "exchange_preflight or order_reconciliation or client_oid or duplicate_order"
```

**验收**：

- symbol/min size 不满足时 blocked 且不下单。
- timeout 后通过 clientOid 恢复，不重复下单。
- `order-status-evidence.json` 被 release bundle 覆盖。
- rejected order 不会被展示为 successful execution。

---

### WS-O：API contract for future frontend without building frontend

**目标**：把“暂不做前端”转成建议做的后端契约，未来任何前端只需要接 OpenAPI。

**建议做**：

1. OpenAPI 完整覆盖：
   - auth
   - release
   - evidence
   - jobs
   - events
   - simulation import
   - publish preflight
   - reconciliation
2. Response envelope 标准化：
   - `ok`
   - `status`
   - `reason_code`
   - `request_id`
   - `job_id`
   - `evidence_hash`
3. Error code：
   - release-specific codes
   - exchange-specific codes
   - auth-specific codes
4. Event stream contract：
   - stable event types
   - monotonic sequence
   - prev_event_hash
   - resumable from sequence
5. CORS：
   - configurable allowed origins
   - no wildcard credentials
6. Contract tests：
   - checked-in OpenAPI matches app
   - examples validate
   - no secret fields appear in schema examples.

**测试**：

```bash
uv run --extra dev pytest -q -k "openapi or service_contract or event_contract or cors"
uv run python scripts/export-service-openapi.py
```

**验收**：

- `schemas/service-openapi.json` 与当前 app 字节一致。
- 所有新 endpoint 有测试覆盖。
- schema example 不含 access key、secret、passphrase。

---

### WS-P：Controlled dependency policy

**目标**：把“不引入依赖”升级为“允许必要依赖，但每个依赖必须证明价值、风险和替代方案”。

**建议做**：

1. 新增 `docs/DEPENDENCY_POLICY.md`：
   - allowed by default：stdlib、已有依赖
   - requires ADR：runtime dependency
   - requires security note：network/crypto/parser dependency
   - forbidden in verdict path：LLM/net/time/random/native/non-deterministic dependency
2. 新增 dependency audit script：
   - lockfile changed check
   - license summary
   - known CVE command if available
   - import path check
3. ADR template：
   - problem
   - chosen dependency
   - alternatives
   - risk
   - removal plan
4. CI gate：
   - pyproject unchanged unless ADR exists
   - verdict path dependency unchanged

**测试**：

```bash
uv run --extra dev pytest -q -k "dependency_policy"
uv run python scripts/check-verdict-path-imports.py
```

**验收**：

- 新 runtime dependency 没有 ADR 时 gate fails。
- verdict path 引入 forbidden import 时 gate fails。
- pyproject 不变时 gate passes。

---

### WS-Q：Observability / operations / production smoke

**目标**：让评委和未来部署者能判断服务是否健康、是否卡单、是否证据断链。

**建议做**：

1. Health endpoints：
   - `/health`
   - `/ready`
   - `/v1/release-safety`
2. Metrics JSON：
   - queued jobs
   - running jobs
   - failed jobs
   - reconciliation_required count
   - last Bitget demo execution timestamp
   - artifact root health
   - DB migration status
3. Structured logs：
   - request_id
   - principal_id
   - release_id
   - job_id
   - reason_code
   - no secrets
4. Production smoke script：
   - start service
   - auth smoke
   - create release
   - import evidence
   - run verify-chain
   - no Bitget key path smoke
   - optional Bitget demo key path smoke
5. Remote smoke:
   - public health
   - OpenAPI parity
   - token 401/403
   - evidence endpoint
   - judge job dry-run.

**测试**：

```bash
uv run --extra dev pytest -q -k "health or readiness or observability or production_smoke"
```

**验收**：

- readiness fails when migrations pending.
- logs do not contain secret keywords.
- smoke can run without Bitget keys and prove zero-key verification.

---

## 6. 推荐优先级

### P0：评委最有感，且后端价值最高

1. WS-H：Backend live judge control plane。
2. WS-N：Exchange preflight/order reconciliation。
3. WS-K：GetAgent Studio/simulation evidence import。
4. WS-O：API contract for future frontend。

### P1：生产完整度

5. WS-L：Production auth/RBAC/audit principal。
6. WS-M：Versioned migrations/database durability。
7. WS-I：Playbook import/publish preflight。
8. WS-Q：Observability/operations。

### P2：谨慎推进

9. WS-J：Mainnet readiness runway。
10. WS-P：Controlled dependency policy。

---

## 7. Definition of Done

v3 完成必须满足：

1. `uv run --extra dev pytest -q` 全绿。
2. `uv run python scripts/check-verdict-path-imports.py` 退 0。
3. `uv run python scripts/export-service-openapi.py` 后 checked-in OpenAPI 无 diff。
4. `scripts/release-demo.sh` 能生成至少 3 笔多样化 demo-only showcase evidence。
5. `uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json` 退 0。
6. `scripts/tamper-demo.sh` 非零退出并显示精确 reason_code。
7. GetAgent Studio/CSV/JSON simulation import 有 raw hash 和 normalized summary hash。
8. Demo order 有 preflight evidence、execution evidence、order status evidence、reconciliation result。
9. judge job API 支持 idempotent retry，不重复下单。
10. release evidence bundle 覆盖 simulation、risk、approval、execution、order status、attestation。
11. README、SERVICE_API、BACKEND_COMPLETENESS、PRODUCTION_RELEASE_BACKEND 与实际能力一致。
12. 所有新 endpoint 和 CLI 不输出、不保存、不渲染 access key、secret key、passphrase。

---

## 8. 仍然不可做的硬红线

这些不是“不建议”，而是不能做：

1. 不能把 LLM 放入 verdict 决策路径。
2. 不能在 verdict 路径联网拉行情或调用交易所。
3. 不能默认开启 mainnet order。
4. 不能绕过 approval/RBAC/state transition 直接下单。
5. 不能在 artifact、HTML、OpenAPI example、日志里写入真实密钥。
6. 不能把 hash-only 当作 verified verdict。
7. 不能为了展示把失败 order 伪造成成功。
8. 不能在无 reconciliation 的情况下宣称 release ready。
9. 不能用请求体里的 reviewer_id 代表真实审批人。
10. 不能让同一 idempotency key + 不同 body 静默复用结果。

---

## 9. 建议新建进度文件模板

新一轮执行前创建 `CODEX_PROGRESS_BACKEND_V3.md`：

```markdown
# CODEX_PROGRESS_BACKEND_V3

## Rules
- 每轮只做一个任务。
- 先写测试/contract，再实现。
- gate 红则不勾选。
- 触碰 auth/execution/verdict/signing/publish 标 human-review。
- 不自动 commit，除非用户明确要求。

## WS-H Backend live judge control plane
- [ ] H.1 judge action job API + idempotency | gate: `pytest -k "judge_job and idempotency"` | last: —
- [ ] H.2 durable event ledger + NDJSON stream | gate: `pytest -k event_chain` | last: —
- [ ] H.3 multi-order showcase scenarios | gate: `pytest -k demo_showcase` | last: —
- [ ] H.4 bad release blocked with Bitget-not-called evidence | gate: `pytest -k "showcase and blocked"` | last: —

## WS-N Exchange preflight/reconciliation
- [ ] N.1 account/symbol/product preflight evidence | gate: `pytest -k exchange_preflight` | last: —
- [ ] N.2 clientOid timeout recovery | gate: `pytest -k client_oid` | last: —
- [ ] N.3 order-status-evidence bundle coverage | gate: `pytest -k order_status_evidence` | last: —

## WS-K Simulation import
- [ ] K.1 raw CSV/JSON upload with source_file_hash | gate: `pytest -k simulation_file_import` | last: —
- [ ] K.2 GetAgent Studio parser + normalized summary | gate: `pytest -k getagent` | last: —
- [ ] K.3 bundle verify covers raw + normalized hashes | gate: `pytest -k normalized_summary` | last: —

## WS-O API contract
- [ ] O.1 OpenAPI for jobs/events/reconciliation/import | gate: `pytest -k openapi` | last: —
- [ ] O.2 event schema + examples + no-secret tests | gate: `pytest -k event_contract` | last: —

## Blocked / Human Review
- —
```

---

## 10. 推荐启动命令

```bash
uv run --extra dev pytest -q -k "judge_job or event_chain or demo_showcase or exchange_preflight or order_reconciliation or simulation_file_import or getagent or openapi"
uv run python scripts/check-verdict-path-imports.py
uv run python scripts/export-service-openapi.py
scripts/release-demo.sh
uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json
scripts/tamper-demo.sh
```

---

## 11. 给下一轮 Codex 的执行提示

1. 先读 `CODEX_GOAL_BACKEND_V3_RECOMMENDED.md`、`CODEX_PROGRESS.md`、如果已存在再读 `CODEX_PROGRESS_BACKEND_V3.md`。
2. 不要继续扩大前端范围；把所有“实时展示”都落实为后端 job/event/evidence。
3. 优先做评委能直接感知的后端闭环：实时 job、多笔 demo order、order reconciliation、GetAgent simulation import。
4. 不要把已有 v2 改动重写成另一套机制；复用 `release.py`、`transitions.py`、`bitget_execution.py`、`render.py`、`chain.py`、`attestation.py`。
5. 每做一个 endpoint 同步测试、OpenAPI、SERVICE_API。
6. 每做一个 evidence 文件，同步 hash 校验、bundle 覆盖、tamper 测试。
7. 每次碰下单路径，先证明 bad release 不调用 Bitget，再证明 good release demo-only 下单。
8. 每次碰身份/审批路径，先证明未授权/自审/过期/已消费会 blocked。
9. 收尾必须跑：pytest、verdict purity gate、OpenAPI export、release demo、verify-chain、tamper-demo。

