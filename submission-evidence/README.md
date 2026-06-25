# Submission evidence: verify it yourself in about 2 minutes, offline

**Playbook Redline is the pre-release control gate for AI-edited trading strategies.** It runs a fixed crash-test suite on the edited playbook, signs the verdict into a hash-chained ed25519 receipt, and places a **real Bitget demo order only after PASS**. Failing edits are **withheld before they can ever trade**.

> This folder lets a judge confirm the whole claim from a fresh clone, **no server, no secrets, no network**. Every command below was captured into the `.txt`/`.json` files next to this README. Re-run them and you will get the same result.

## The sequence (and where to see each step)

| Step | What it proves | Run this | Expect | Captured |
|---|---|---|---|---|
| 1. Gate | An AI-edited strategy is **crash-tested**; a bad edit is **WITHHELD** (no order), a good one passes | `make verify-demo` | exit `0` (pass→pass, withheld→`NEW_BLOCK_BREACH`) | [`01-gate-crash-test.txt`](01-gate-crash-test.txt) |
| 2. Receipt | The PASS verdict is sealed into a **hash-chained** release bundle | `redline verify-release-bundle <bundle>` | exit `0`, `chain-checkpoint-link ok` | [`02-verify-release-bundle.txt`](02-verify-release-bundle.txt) |
| 3. Signature | The bundle is **ed25519-signed** with a merkle root over the evidence | `redline verify-release-attestation <att> --bundle <bundle>` | exit `0` | [`03-verify-release-attestation.txt`](03-verify-release-attestation.txt) |
| 4. Real order | A **real Bitget demo/paptrading order** was placed **only after** PASS, bound by hash to the receipt | see file | `order_mode: demo`, `reason_code: PASS` | [`05-real-bitget-order.json`](05-real-bitget-order.json) |
| 5. Tamper | Flip one byte → the seal **fails closed** | `bash scripts/tamper-demo.sh` | exit `4`, `release evidence bundle is not valid` | [`04-tamper-fail-closed.txt`](04-tamper-fail-closed.txt) |
| 5b. Tamper (in-browser) | Same, interactively: edit the JSON → randomart seal deforms → `INTEGRITY FAIL` | open the offline verify page and change one character | seal turns red | [before](screenshots/tamper-1-intact.png) · [after](screenshots/tamper-2-fail.png) |

**Visual proof, the seal breaking when one byte is flipped (offline, pure-JS):**

![Offline tamper check: flip one byte, the randomart seal voids, the verdict flips to INTEGRITY FAIL, and Bitget was never called](tamper.gif)

## Copy-paste reproduce (fresh clone)

```bash
git clone <repo> && cd playbook-redline
uv sync                                   # or: pip install -e .
B=artifacts/release-demo/current/service/releases/release-demo-good/release-evidence-bundle.json
A=artifacts/release-demo/current/service/releases/release-demo-good/release-attestation.json

make verify-demo                          # 1. gate: PASS vs WITHHELD          -> exit 0
uv run redline verify-release-bundle      "$B" --json   # 2. hash-chain        -> exit 0
uv run redline verify-release-attestation "$A" --bundle "$B" --json  # 3. ed25519 -> exit 0
bash scripts/tamper-demo.sh               # 5. flip a byte -> fail closed       -> exit 4
open artifacts/evidence-tamper-check.html # 5b. interactive byte-flip
```

The real demo order id (`1453610833413308417`) is a **non-secret Bitget demo id**; no API keys, secrets, or mainnet funds are involved (`paptrading:1`, demo only).

> The crash-test suite is **fixed**, so the AI cannot move the goalposts after editing its own strategy. A PASS is what places the real Bitget demo order; a FAIL withholds it.
