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
