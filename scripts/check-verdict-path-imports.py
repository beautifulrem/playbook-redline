from __future__ import annotations

import ast
import sys
from pathlib import Path


CHECK_PATHS = (
    Path("src/redline/engine_adapter/deterministic.py"),
    Path("src/redline/engine_adapter/sandbox_process.py"),
    Path("src/redline/proof_kernel.py"),
    Path("src/redline/receipt.py"),
    Path("src/redline/runner.py"),
    Path("src/redline/tripwire.py"),
    Path("src/redline/verifier.py"),
    Path("src/redline/probes"),
)

# The sandbox-worker spawn boundary legitimately needs subprocess. Allowlisting only this
# exact (file, module) keeps the gate scanning that file — so a future net/LLM/ctypes
# import there is still caught — while permitting the sanctioned isolation primitive.
SANCTIONED_IMPORTS = (("sandbox_process.py", "subprocess"),)

FORBIDDEN_MODULES = (
    "aiohttp",
    "anthropic",
    "cffi",
    "ctypes",
    "dashscope",
    "datetime",
    "google.generativeai",
    "http",
    "httpx",
    "openai",
    "random",
    "requests",
    "secrets",
    "socket",
    "subprocess",
    "time",
    "urllib",
    "urllib3",
    "uuid",
    "websocket",
    "websockets",
    "xai_sdk",
)

FORBIDDEN_CALLS = ("float", "frozenset", "set")


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


def _sanctioned(path: Path, module: str) -> bool:
    base = module.split(".")[0]
    return any(path.name == name and base == mod for name, mod in SANCTIONED_IMPORTS)


def scan_file(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _is_forbidden(alias.name) and not _sanctioned(path, alias.name):
                    findings.append(f"{path}:{node.lineno}: forbidden import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            module_name = node.module or ""
            if _is_forbidden(module_name) and not _sanctioned(path, module_name):
                findings.append(f"{path}:{node.lineno}: forbidden import {module_name}")
        elif isinstance(node, ast.Call):
            call_name = _call_name(node.func)
            if isinstance(node.func, ast.Name) and call_name in FORBIDDEN_CALLS:
                findings.append(f"{path}:{node.lineno}: forbidden deterministic builtin call {call_name}()")
            if call_name in {"__import__", "importlib.import_module"} and node.args:
                module_name = _string_arg(node.args[0])
                if module_name is not None and _is_forbidden(module_name):
                    findings.append(f"{path}:{node.lineno}: forbidden dynamic import {module_name}")
        elif isinstance(node, ast.Set):
            findings.append(f"{path}:{node.lineno}: forbidden set literal in verdict path")
        elif isinstance(node, ast.SetComp):
            findings.append(f"{path}:{node.lineno}: forbidden set comprehension in verdict path")
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
