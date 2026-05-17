from __future__ import annotations

import re
from pathlib import Path
from .models import ContractInfo, FunctionInfo

CONTRACT_RE = re.compile(r"\b(?:abstract\s+)?(?:contract|interface|library)\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)(?:\s+is\s+(?P<inherits>[^\{]+))?\s*\{")
STATE_VAR_RE = re.compile(r"^\s*(?:mapping\s*\([^;]+\)|[A-Za-z_][A-Za-z0-9_<>\[\]]*)\s+(?:public|private|internal|external)?\s*(?:constant|immutable)?\s*(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)", re.MULTILINE)
FUNCTION_RE = re.compile(r"\bfunction\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)?\s*\((?P<args>[^)]*)\)\s*(?P<header>[^\{;]*)\{", re.MULTILINE)

VISIBILITIES = {"public", "external", "internal", "private"}


def strip_comments(source: str) -> str:
    source = re.sub(r"/\*.*?\*/", "", source, flags=re.DOTALL)
    source = re.sub(r"//.*", "", source)
    return source


def find_matching_brace(text: str, open_index: int) -> int:
    depth = 0
    for i in range(open_index, len(text)):
        if text[i] == "{":
            depth += 1
        elif text[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return len(text) - 1


def line_number_at(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def parse_solidity_file(path: Path, root: Path) -> list[ContractInfo]:
    raw = path.read_text(encoding="utf-8", errors="ignore")
    source = strip_comments(raw)
    contracts: list[ContractInfo] = []

    for match in CONTRACT_RE.finditer(source):
        name = match.group("name")
        inherits_raw = match.group("inherits") or ""
        inherits = [x.strip().split("(")[0].strip() for x in inherits_raw.split(",") if x.strip()]
        body_start = source.find("{", match.end() - 1)
        body_end = find_matching_brace(source, body_start)
        body = source[body_start + 1:body_end]

        state_vars = []
        for sv in STATE_VAR_RE.finditer(body):
            var_name = sv.group("name")
            if var_name not in {"if", "for", "while", "return", "emit", "require"}:
                state_vars.append(var_name)

        functions: list[FunctionInfo] = []
        for fm in FUNCTION_RE.finditer(body):
            fn_name = fm.group("name") or "fallback"
            header = fm.group("header") or ""
            f_open = body.find("{", fm.end() - 1)
            f_end = find_matching_brace(body, f_open)
            f_body = body[f_open + 1:f_end]
            tokens = re.findall(r"[A-Za-z_][A-Za-z0-9_]*", header)
            visibility = next((t for t in tokens if t in VISIBILITIES), None)
            modifiers = [t for t in tokens if t not in VISIBILITIES and t not in {"payable", "view", "pure", "virtual", "override", "returns"}]
            absolute_start = body_start + 1 + fm.start()
            absolute_end = body_start + 1 + f_end
            functions.append(FunctionInfo(
                contract=name,
                name=fn_name,
                signature=f"{fn_name}({fm.group('args').strip()})",
                visibility=visibility,
                modifiers=modifiers,
                payable="payable" in tokens,
                view_or_pure=("view" in tokens or "pure" in tokens),
                body=f_body.strip(),
                line_start=line_number_at(source, absolute_start),
                line_end=line_number_at(source, absolute_end),
            ))

        contracts.append(ContractInfo(
            name=name,
            path=str(path.relative_to(root)),
            inherits=inherits,
            state_variables=sorted(set(state_vars)),
            functions=functions,
        ))
    return contracts


def collect_contracts(root: str | Path) -> list[ContractInfo]:
    root = Path(root).resolve()
    files = sorted(root.rglob("*.sol"))
    contracts: list[ContractInfo] = []
    for file in files:
        if any(part in {"node_modules", "lib", "out", "cache"} for part in file.parts):
            continue
        contracts.extend(parse_solidity_file(file, root))
    return contracts
