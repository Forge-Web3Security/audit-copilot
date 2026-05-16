from __future__ import annotations

import json

from pathlib import Path
from .contest_filters import generate_findings
from .invariants import generate_invariants
from .modeler import build_protocol_model
from .models import AnalysisResult, Platform
from .reporting import write_json, write_markdown
from .analysis.hypothesis_engine import generate_hypotheses, hypotheses_to_markdown
from .scanners import load_aderyn, load_mythril, load_slither
from .session import apply_context_to_hypotheses, load_audit_context
from .solidity_parser import collect_contracts
from .transitions import extract_transitions


def analyze_project(root: str | Path, platform: Platform = Platform.generic, slither_json: str | None = None, aderyn_json: str | None = None, mythril_json: str | None = None) -> AnalysisResult:
    contracts = collect_contracts(root)
    model = build_protocol_model(root, contracts)
    transitions = extract_transitions(contracts)
    invariants = generate_invariants(model, transitions)
    scanner_signals = load_slither(slither_json) + load_aderyn(aderyn_json) + load_mythril(mythril_json)
    findings = generate_findings(platform, transitions, invariants, scanner_signals)
    return AnalysisResult(
        platform=platform,
        model=model,
        transitions=transitions,
        invariants=invariants,
        scanner_signals=scanner_signals,
        findings=findings,
    )


def write_outputs(result: AnalysisResult, out: str | Path, context_path: str | Path | None = None) -> None:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)

    write_json(result, out)
    write_markdown(result, out)

    analysis_payload = json.loads(result.model_dump_json())
    hypotheses = generate_hypotheses(analysis_payload)

    if context_path is not None:
        audit_context = load_audit_context(context_path)
        hypotheses = apply_context_to_hypotheses(hypotheses, audit_context)

    (out / "hypotheses.json").write_text(
        json.dumps([h.model_dump() for h in hypotheses], indent=2)
    )
    (out / "hypotheses.md").write_text(hypotheses_to_markdown(hypotheses))
