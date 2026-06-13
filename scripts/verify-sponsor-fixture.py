from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

from redline.canonical import hash_tree, sha256_bytes
from redline.surfaces import make_receipt_bound_package_archive
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
        archive, _annotation = make_receipt_bound_package_archive(
            receipt_path=RECEIPT,
            package=PACKAGE,
            annotation_path=Path(tmp) / "redline-annotation.json",
            out_path=Path(tmp) / "annotated-package.tar.gz",
            package_hash=package_hash,
        )
        archive_hash = sha256_bytes(archive.read_bytes())
    expected = {
        "metrics_output_hash": receipt.result.result_hash,
        "expected_metrics_output_hash": receipt.result.result_hash,
        "package_hash": receipt.package.identity_hash,
        "package_archive_hash": archive_hash,
    }
    mismatches = {key: {"actual": evidence.get(key), "expected": value} for key, value in expected.items() if evidence.get(key) != value}
    if package_hash != receipt.package.identity_hash:
        mismatches["package_tree_hash"] = {"actual": package_hash, "expected": receipt.package.identity_hash}
    if mismatches:
        print(json.dumps({"ok": False, "mismatches": mismatches}, indent=2, sort_keys=True))
        return 1
    print(json.dumps({"ok": True, "evidence": str(EVIDENCE.relative_to(ROOT))}, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
