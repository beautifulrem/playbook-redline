from __future__ import annotations

import ast
import sys
from pathlib import Path


CHECK_PATHS = (
    Path("src/redline/proof_kernel.py"),
    Path("src/redline/verifier.py"),
    Path("src/redline/probes"),
)

FORBIDDEN_MODULES = (
    "aiohttp",
    "anthropic",
    "cffi",
    "ctypes",
    "dashscope",
    "google.generativeai",
    "http",
    "httpx",
    "openai",
    "requests",
    "socket",
    "subprocess",
    "urllib",
    "urllib3",
    "websocket",
    "websockets",
    "xai_sdk",
)


def _is_forbidden(module_name: str) -> bool:
    return any(module_name == forbidden or module_name.startswith(forbidden + ".") for forbidden in FORBIDDEN_MODULES)


def _string_arg(node: ast.AST) -> str | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _call_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return None


def _python_files(root: Path, target: Path) -> list[Path]:
    path = root / target
    if path.is_dir():
        return sorted(path.rglob("*.py"))
    return [path] if path.exists() else []


def scan_file(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_forbidden(alias.name):
                    findings.append(f"{path}:{node.lineno}: forbidden import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            if _is_forbidden(module_name):
                findings.append(f"{path}:{node.lineno}: forbidden import {module_name}")
        elif isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if call_name in {"__import__", "importlib.import_module"} and node.args:
                module_name = _string_arg(node.args[0])
                if module_name is not None and _is_forbidden(module_name):
                    findings.append(f"{path}:{node.lineno}: forbidden dynamic import {module_name}")
    return findings


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path.cwd().resolve()
    findings: list[str] = []
    for target in CHECK_PATHS:
        for path in _python_files(root, target):
            findings.extend(scan_file(path))
    if findings:
        print("\n".join(findings), file=sys.stderr)
        return 1
    print("verdict path import gate passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
