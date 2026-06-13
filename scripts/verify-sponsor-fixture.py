from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from redline.canonical import hash_tree, sha256_bytes
from redline.sponsor.bitget import make_package_archive
from redline.verifier import load_receipt


ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "fixtures/demo_pack"
RECEIPT = ROOT / "artifacts/demo/pass/receipt.json"
EVIDENCE = ROOT / "artifacts/sponsor/demo-readback.json"


def main() -> int:
    evidence = json.loads(EVIDENCE.read_text(encoding="utf-8"))
    receipt = load_receipt(RECEIPT)
    package_hash = hash_tree(PACKAGE)
    with tempfile.TemporaryDirectory(prefix="redline-sponsor-fixture-") as tmp:
        archive = make_package_archive(package_dir=PACKAGE, out_path=Path(tmp) / "package.tar.gz")
        archive_hash = sha256_bytes(archive.read_bytes())
    expected = {
        "package_hash": receipt.package.identity_hash,
        "package_archive_hash": archive_hash,
    }
    mismatches = {key: {"actual": evidence.get(key), "expected": value} for key, value in expected.items() if evidence.get(key) != value}
    if evidence.get("expected_metrics_output_hash") is not None and evidence.get("expected_metrics_output_hash") != evidence.get("metrics_output_hash"):
        mismatches["expected_metrics_output_hash"] = {
            "actual": evidence.get("expected_metrics_output_hash"),
            "expected": evidence.get("metrics_output_hash"),
        }
    if package_hash != receipt.package.identity_hash:
        mismatches["package_tree_hash"] = {"actual": package_hash, "expected": receipt.package.identity_hash}
    if mismatches:
        print(json.dumps({"ok": False, "mismatches": mismatches}, indent=2, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "evidence": str(EVIDENCE.relative_to(ROOT))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
