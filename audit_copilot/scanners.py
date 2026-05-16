from __future__ import annotations

import json
from pathlib import Path
from .models import ScannerSignal


def load_slither(path: str | None) -> list[ScannerSignal]:
    if not path:
        return []
    data = json.loads(Path(path).read_text())
    detectors = data.get("results", {}).get("detectors", [])
    signals: list[ScannerSignal] = []
    for d in detectors:
        elements = d.get("elements", []) or []
        first = elements[0] if elements else {}
        source = first.get("source_mapping", {}) if isinstance(first, dict) else {}
        signals.append(ScannerSignal(
            tool="slither",
            check=d.get("check", "unknown"),
            severity=d.get("impact") or d.get("confidence"),
            title=d.get("check", "Slither signal"),
            description=d.get("description", ""),
            contract=first.get("name") if isinstance(first, dict) else None,
            path=source.get("filename_relative") or source.get("filename_absolute"),
            line=(source.get("lines") or [None])[0] if isinstance(source.get("lines"), list) else None,
            raw=d,
        ))
    return signals


def load_aderyn(path: str | None) -> list[ScannerSignal]:
    if not path:
        return []
    data = json.loads(Path(path).read_text())
    raw_findings = data.get("findings") if isinstance(data, dict) else data
    signals: list[ScannerSignal] = []
    for f in raw_findings or []:
        signals.append(ScannerSignal(
            tool="aderyn",
            check=f.get("check") or f.get("detector") or f.get("title", "unknown"),
            severity=f.get("severity") or f.get("impact"),
            title=f.get("title") or f.get("check") or "Aderyn signal",
            description=f.get("description") or f.get("body") or "",
            contract=f.get("contract"),
            function=f.get("function"),
            path=f.get("path") or f.get("file"),
            line=f.get("line"),
            raw=f,
        ))
    return signals


def load_mythril(path: str | None) -> list[ScannerSignal]:
    if not path:
        return []
    data = json.loads(Path(path).read_text())

    if isinstance(data, dict):
        issues = data.get("issues", data.get("results", []))
    else:
        issues = data

    if not isinstance(issues, list):
        issues = []

    signals: list[ScannerSignal] = []
    for issue in issues:
        if not isinstance(issue, dict):
            continue

        check = issue.get("type") or issue.get("swc-id") or issue.get("check", "unknown")
        title = issue.get("title") or issue.get("name") or issue.get("check", "Mythril signal")
        severity = issue.get("severity")
        if severity:
            severity = severity.capitalize()

        contract = issue.get("contract") or issue.get("contract_name")
        function = issue.get("function") or issue.get("function_name")
        description = (
            issue.get("description")
            or issue.get("head")
            or issue.get("body")
            or ""
        )

        line = issue.get("lineno") or issue.get("line")
        source_path = issue.get("source") or issue.get("file") or issue.get("path")

        signals.append(ScannerSignal(
            tool="mythril",
            check=check,
            severity=severity,
            title=title,
            description=str(description)[:2000],
            contract=contract,
            function=function,
            path=source_path,
            line=int(line) if line is not None else None,
            raw=issue,
        ))

    return signals
