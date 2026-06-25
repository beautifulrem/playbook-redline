# Playbook Redline

> AI 改写的策略，得先扛过一套固定的崩溃测试，才能碰到 Bitget。
> 每一次裁决都是一张签名、可验篡改的回执，离线就能校验，不用任何服务器。*没有证明，就没有裁决。*

[English](README.md) · [中文](README_CN.md)

![tests](https://img.shields.io/badge/tests-373%20passing-brightgreen)
![python](https://img.shields.io/badge/python-3.12-3776AB)
![mode](https://img.shields.io/badge/Bitget-demo%20%2F%20paptrading%20only-F7931A)
![MCP](https://img.shields.io/badge/MCP-receipt--check%20tool-7E3FF2)
![license](https://img.shields.io/badge/license-MIT-blue)

**在线 demo**（免安装、免登录）：<https://beautifulrem.github.io/playbook-redline/>

Playbook Redline 是给 AI 改写交易策略用的发布前校验闸。AI 改一份 playbook，Redline 不信这段 diff：它把改完的策略放进固定崩溃测试里重放，裁决生成一张 ed25519 签名的哈希链回执；套件全过，才真下一笔 Bitget 模拟单。没过的改动，下单前就拦住。

<p align="center">
  <img src="submission-evidence/tamper.gif" width="78%" alt="离线篡改校验：改一个字节，randomart 印章作废，裁决翻成 INTEGRITY FAIL，证据显示全程没调用过 Bitget">
</p>
<p align="center"><sub>离线、纯 JS 的篡改校验。把回执里的一个字节改掉，randomart 印章就作废，裁决翻成 <b>INTEGRITY FAIL</b>，证据里能看到全程没调用过 Bitget。</sub></p>

## 自己动手验证

一次 60 秒、零密钥的评委复核：离线，不用服务器，也不用任何 Bitget 凭证。下面每一步都记录在 [`submission-evidence/`](submission-evidence/) 里，从全新 clone 就能复跑。这条路只用 demo，证据来自 Bitget `paptrading: 1`，不代表 Bitget Playbook 正式发布。

```bash
uv run redline verify-chain artifacts/release-demo/current/service/releases/release-demo-good --json  # 通过的链式发布
bash scripts/tamper-demo.sh                                                                            # 翻一个字节，完整性校验直接失败 -> exit 4
open artifacts/release-demo/current/evidence.html                                                      # 只读的评委证据页
```

`verify-chain` 会输出一个通过的链式发布；tamper 脚本改过 bundle 后会校验失败，以非零码退出；HTML 是只读的评委证据页。这条复核路不用 Bitget demo 凭证；只有重跑 `scripts/release-demo.sh` 去下新的 demo 单时才需要。

真实模拟单 `1453610833413308417` 来自 Bitget `paptrading: 1`，仅用于 demo，不碰主网、不用密钥（见 [`submission-evidence/05-real-bitget-order.json`](submission-evidence/05-real-bitget-order.json)）。

## 工作原理

1. AI 改一份交易 playbook。Redline 验的是改完的策略本身，不是 diff 说了什么。
2. Redline 把候选策略放进一套**固定**的崩溃测试里重放：最大回撤、暴跌窗口不入场、交易预算。固定套件是刻意的：不能让 AI 改完自己的策略，又回头去挪判分线。
3. 没过，候选就扣下，不下任何单。
4. 过了，裁决写进一张哈希链、ed25519 签名的回执，并在 `paptrading: 1` 下真下一笔 Bitget 模拟单。
5. 这张回执谁都能离线复验。改掉一个字节，链就断、签名就失效、印章就作废。

## 集成

Redline 夹在「改策略的 AI」和交易所中间。三种接法。

### CI 里的 CLI

在流水线里卡住这次改动。候选被拦下时 `redline run` 以非零码退出，所以 CI 这一步会在坏改动发出去之前让构建失败。这个仓库本身也是一个 composite GitHub Action：

```yaml
# .github/workflows/redline.yml
jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: beautifulrem/playbook-redline@main
        with:
          package: fixtures/demo_pack
          candidate: candidate_good            # 你改完的发布候选
          # allow-amber-baseline-genesis: "true"   # 仅用于内置的 genesis demo
```

这个 action 会跑 `redline doctor` 和 `redline run`，上传回执 / 报告 / 证明产物，并按裁决判定成败。或者直接调 CLI，用退出码当闸门：

```bash
uv run redline run "$PKG" --baseline baseline --candidate "$EDIT" \
  --suite fixtures/suites/demo_suite.json --spec fixtures/specs/redline_spec.json \
  --out artifacts/ci --json
uv run redline verify-release-bundle "$BUNDLE" --json   # 发出去之前再核一遍封好的 bundle
```

退出码就是约定：`0` 是 PASS，非零是被拦下或被篡改（比如 `4` 表示完整性失败），`10` 是琥珀色的 `BASELINE_GENESIS`（没有接到上一张回执的基线）。`make verify-demo` 会把「坏改动被拦、好改动通过」整条流程跑一遍。

### HTTP 服务

从编排器驱动同一个内核。服务是一层薄 FastAPI 边界：不调 CLI，也不另开一条裁决路径（worker 直接调 `run_redline`，把每次运行的产物放在各自隔离的目录里）。

```bash
REDLINE_SERVICE_TOKEN=redline-demo uv run redline-api
```

```bash
H='-H x-redline-token:redline-demo -H content-type:application/json'

curl -s -H x-redline-token:redline-demo http://127.0.0.1:8080/health
curl -s -X POST $H http://127.0.0.1:8080/v1/packages/import -d '{"package_path":"fixtures/demo_pack"}'

RUN=$(curl -s -X POST $H http://127.0.0.1:8080/v1/runs \
  -d '{"package_path":"fixtures/demo_pack","candidate":"candidate_good"}' | jq -r .run_id)
curl -s -H x-redline-token:redline-demo "http://127.0.0.1:8080/v1/runs/$RUN"     # 轮询裁决

curl -s -X POST $H "http://127.0.0.1:8080/v1/runs/$RUN/execute"                  # 闸门
```

`POST /v1/runs/{run_id}/execute` 是执行闸门：它只收一张重放通过、已接链、已签名的 `PASS` 回执，在 `paptrading: 1` 下下一笔 Bitget 模拟单。WITHHELD、纯哈希、未签名、未接链、被篡改、缺凭证、默认主网这些情况，都会在调用下单之前返回 `blocked`。发布后端在这之上又叠了版本化发布、模拟交易证据、风险策略绑定、人工审批，以及一份哈希校验过的证据包；`/v1/judge/console` 渲染一个只读的评审界面。OpenAPI 契约签入在 `schemas/service-openapi.json`；完整端点语义见 [`SERVICE_API.md`](SERVICE_API.md)，部署见 [`DEPLOYMENT.md`](DEPLOYMENT.md)。

### MCP 服务（给 agent 用）

Redline 带了一个很窄的 [MCP](https://modelcontextprotocol.io) 服务，让 AI agent 在对话里就能验一张回执。它只注册**一个只读工具**，从不替调用方跑裁决逻辑：agent 能查结果，但动不了结果，没法靠这个工具把 WITHHELD 变成 PASS。

用 stdio 跑起来：

```bash
uv run redline-mcp
```

接进任意 MCP 客户端（Claude Desktop、agent 运行时、IDE）：

```json
{
  "mcpServers": {
    "playbook-redline": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/playbook-redline", "redline-mcp"]
    }
  }
}
```

只有一个工具 **`redline_check_receipt`**，验一张回执，不动任何 package 或平台状态：

- `receipt_path`（必填）：要验的回执。
- `pkg_path`（选填）：给了它，Redline 就**重放** package 重新推出裁决；不给就是纯哈希校验（只验完整性，不是裁决）。
- 返回 `status`、`reason_code`、`receipt_hash`、`chain_status`、`proof_coverage`（schema `redline.mcp.check.v1`）。

典型的 agent 回路：agent 改完 playbook，跑闸门（CLI 或 `POST /v1/runs`），在它信这个 PASS、或往下游发任何东西之前，先对生成的回执调一次 `redline_check_receipt`。裁决路径从设计上就够不着 agent。

## 安装

先决条件：Python 3.12 和 [uv](https://docs.astral.sh/uv/)（或 `pip install -e .`）。

```bash
make install
make audit
uv run redline doctor --json
make goldens-check
```

预期的 demo 结果：

- `candidate_good`：`pass`，带 `BASELINE_GENESIS`
- `candidate_bad`：`withheld`，带 `NEW_BLOCK_BREACH`

内置套件是两段 24 根 K 线的 BTCUSDT 窗口，外加三个阻断式探针（最大回撤、暴跌窗口不入场、交易预算）。`BASELINE_GENESIS` 用退出码 `10` 表示一个琥珀（amber）状态，因为夹具基线没有接到上一张回执。纯哈希检查只验完整性，返回 `unverified_no_verdict`；可信校验走的是绑定包的重放。

## 用法

跑闸门，再校验回执：

```bash
uv run redline run fixtures/demo_pack \
  --baseline baseline --candidate candidate_bad \
  --suite fixtures/suites/demo_suite.json \
  --spec fixtures/specs/redline_spec.json \
  --out artifacts/demo/withheld --json

uv run redline verify-proof artifacts/demo/pass/receipt.json \
  --proof-id proof:package_canonical:7bc11572ef15a4a40cdf1856 \
  --package fixtures/demo_pack \
  --suite fixtures/suites/demo_suite.json \
  --spec fixtures/specs/redline_spec.json --json
```

`redline report` 不带 `--verified` 时只渲染 `UNVERIFIED PREVIEW`。最终发布得有两样东西：一张链式 `PASS` 回执，和一份 ed25519 签名的账本背书（背书要按固定 trust policy 校验通过）；内置的 genesis 夹具不算。信任密钥生成、账本签名、对接交易所的 publish 流程，都写在 CLI 帮助和 [`SERVICE_API.md`](SERVICE_API.md) 里。

## 安全边界

候选策略跑在子进程里。在 macOS 上，worker 还额外套一层 `sandbox-exec`，禁掉网络、进程 fork 和文件写入。worker 内部用 Python 审计钩子，禁掉 socket、subprocess、fork、exec、文件改动、读取包和运行时白名单以外的路径，以及 `ctypes`/`cffi`。场景数据由可信代码预加载，从不以可读文件的形式给到候选策略。裁决路径只用内置探针，另有一道 tripwire 挡掉网络和 LLM SDK 的 import。这是给 demo 和 CI 用的本地证明内核沙箱；生产环境的交易所执行，仍该用交易所自己的运行时沙箱。

## 仓库结构

```text
src/redline/      后端包
tests/            后端测试
fixtures/         demo 包、套件、spec
schemas/          导出的 JSON schema
artifacts/demo/   签入的 demo 回执和证明产物
scripts/          辅助校验脚本
SERVICE_API.md    服务 API 契约
DEPLOYMENT.md     容器部署和评委 runbook
```

为 Bitget AI Hackathon 的 Trading Infra 赛道而做。demo 执行只用 Bitget `paptrading: 1`，不代表 Playbook 真实上线。

## 许可证

[MIT](LICENSE) © 2026 Playbook Redline contributors.
