"""Prepare stage: build a lightweight Code Property Graph (CPG) for a repo
without requiring a build step — a file inventory, per-file symbol table,
and an entrypoint map (HTTP routes) so later stages know what is
attacker-reachable.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path

SOURCE_EXTS = {".py", ".js"}
SKIP_DIRS = {"node_modules", "__pycache__", ".git", "venv", ".venv"}

FLASK_ROUTE_RE = re.compile(r"@\w+\.route\(\s*[\"']([^\"']+)[\"']")
EXPRESS_ROUTE_RE = re.compile(r"router\.(get|post|put|delete|patch)\(\s*[\"']([^\"']+)[\"']")


@dataclass
class Entrypoint:
    file: str
    line: int
    method: str
    path: str
    handler: str


@dataclass
class FileNode:
    path: str
    language: str
    functions: list = field(default_factory=list)
    imports: list = field(default_factory=list)
    loc: int = 0


@dataclass
class CodePropertyGraph:
    repo: str
    root: str
    files: list  # list[FileNode]
    entrypoints: list  # list[Entrypoint]

    def summary(self) -> dict:
        return {
            "repo": self.repo,
            "file_count": len(self.files),
            "entrypoint_count": len(self.entrypoints),
            "loc": sum(f.loc for f in self.files),
            "languages": sorted({f.language for f in self.files}),
        }


def _walk_source_files(root: Path):
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        if p.suffix in SOURCE_EXTS:
            yield p


def _prepare_python_file(path: Path, rel: str) -> tuple[FileNode, list[Entrypoint]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    node = FileNode(path=rel, language="python", loc=text.count("\n") + 1)
    entrypoints: list[Entrypoint] = []
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return node, entrypoints

    for item in ast.walk(tree):
        if isinstance(item, ast.Import):
            node.imports.extend(a.name for a in item.names)
        elif isinstance(item, ast.ImportFrom) and item.module:
            node.imports.append(item.module)
        elif isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
            node.functions.append(item.name)
            for dec in item.decorator_list:
                dec_src = ast.unparse(dec) if hasattr(ast, "unparse") else ""
                m = re.search(r"route\(\s*[\"']([^\"']+)[\"']", dec_src)
                if m:
                    methods = ["GET"]
                    mm = re.search(r"methods\s*=\s*\[([^\]]+)\]", dec_src)
                    if mm:
                        methods = [x.strip(" '\"") for x in mm.group(1).split(",")]
                    for method in methods:
                        entrypoints.append(
                            Entrypoint(
                                file=rel,
                                line=item.lineno,
                                method=method,
                                path=m.group(1),
                                handler=item.name,
                            )
                        )
    return node, entrypoints


def _prepare_js_file(path: Path, rel: str) -> tuple[FileNode, list[Entrypoint]]:
    text = path.read_text(encoding="utf-8", errors="ignore")
    node = FileNode(path=rel, language="javascript", loc=text.count("\n") + 1)
    entrypoints: list[Entrypoint] = []

    node.imports = re.findall(r"require\(\s*[\"']([^\"']+)[\"']\s*\)", text)
    node.functions = re.findall(r"function\s+(\w+)\s*\(", text)

    for lineno, line in enumerate(text.splitlines(), start=1):
        m = EXPRESS_ROUTE_RE.search(line)
        if m:
            entrypoints.append(
                Entrypoint(
                    file=rel,
                    line=lineno,
                    method=m.group(1).upper(),
                    path=m.group(2),
                    handler=m.group(2),
                )
            )
    return node, entrypoints


def prepare_repo(repo_name: str, repo_path: str) -> CodePropertyGraph:
    root = Path(repo_path)
    files: list[FileNode] = []
    entrypoints: list[Entrypoint] = []

    for src in _walk_source_files(root):
        rel = str(src.relative_to(root)).replace("\\", "/")
        if src.suffix == ".py":
            fnode, eps = _prepare_python_file(src, rel)
        else:
            fnode, eps = _prepare_js_file(src, rel)
        files.append(fnode)
        entrypoints.extend(eps)

    return CodePropertyGraph(repo=repo_name, root=str(root), files=files, entrypoints=entrypoints)
