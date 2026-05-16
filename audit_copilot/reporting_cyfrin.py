from __future__ import annotations

from pathlib import Path
from typing import Any

from .analysis.hypothesis_engine import Hypothesis, hypotheses_to_markdown
from .models import AnalysisResult


def generate_cyfrin_report(
    result: AnalysisResult,
    hypotheses: list[Hypothesis],
    platform: str = "sherlock",
    findings_data: list[dict[str, Any]] | None = None,
) -> str:
    """Generate a full Cyfrin-format audit report."""
    if findings_data is None:
        findings_data = []

    contracts_table = "\n".join(
        f"| {c.name} | {c.path} | {', '.join(c.inherits) if c.inherits else '-'} |"
        for c in result.model.contracts
    ) or "| - | - | - |"

    findings_sections = ""
    for f in findings_data:
        poc = "\n".join(f"1. {step}" for step in f.get("proof_of_concept", []))
        validity = "\n".join(f"- {note}" for note in f.get("contest_validity", []))
        findings_sections += f"""
### [{f['severity'].upper()}] {f['title']}

**Description:**
{f['description']}

**Impact:**
{f['impact']}

**Affected Contracts:** {', '.join(f['affected_contracts']) if f['affected_contracts'] else 'N/A'}
**Affected Functions:** {', '.join(f['affected_functions']) if f['affected_functions'] else 'N/A'}

**Proof of Concept:**
{poc if poc else '- No PoC available'}

**Recommended Mitigation:**
{f.get('recommended_mitigation', 'No mitigation suggested.')}

**Contest Validity:**
{validity if validity else '- Standard severity classification applies.'}

---
"""

    if not findings_data:
        findings_sections = "*No confirmed findings.*"

    return f"""# Audit Report
**Platform:** {platform.upper()}
**Protocol Root:** {result.model.root}

---

## Executive Summary

This report contains the findings from a security review of the protocol.

- **Contracts analyzed:** {len(result.model.contracts)}
- **State transitions extracted:** {len(result.transitions)}
- **Candidate invariants:** {len(result.invariants)}
- **Scanner signals processed:** {len(result.scanner_signals)}
- **Total hypotheses generated:** {len(hypotheses)}

---

## Protocol Summary

| Metric | Value |
|---|---|
| Platform Mode | {result.platform.value} |
| Contracts | {len(result.model.contracts)} |
| Actors | {', '.join(result.model.actors) if result.model.actors else 'N/A'} |
| Privileged Roles | {', '.join(result.model.privileged_roles) if result.model.privileged_roles else 'N/A'} |
| Assets | {', '.join(result.model.assets) if result.model.assets else 'N/A'} |
| Integrations | {', '.join(result.model.integrations) if result.model.integrations else 'N/A'} |

## Assets In Scope

| Contract | Path | Inherits |
|---|---|---|
{contracts_table}

---

## Findings

{findings_sections}

---

## Invariant Tests

{chr(10).join(f'- **{i.id}**: {i.title} — {i.description}' for i in result.invariants) if result.invariants else '- No invariants identified.'}

---

## Hypotheses Generated

{hypotheses_to_markdown(hypotheses)}

---

## Attack Surfaces Reviewed

- **Access Control:** Role assignment, ownership transfer, privilege escalation
- **Accounting:** Share/asset conversion, balance tracking, reward calculation
- **External Calls:** Reentrancy, CEI violations, callback safety
- **Oracle/Price:** Spot price manipulation, stale price, decimal mismatch
- **Economic:** Donation attacks, rounding, fee extraction
- **State Machine:** Initialization, pause, upgrade, shutdown

---

## Recommended Next Steps

1. Fix all High/Critical findings before deployment
2. Run invariant fuzzing with Foundry on fixed code
3. Perform mitigation review after fixes are applied
4. Consider formal verification for core accounting math
"""


def write_cyfrin_report(
    result: AnalysisResult,
    hypotheses: list[Hypothesis],
    out: Path,
    platform: str = "sherlock",
    findings_data: list[dict[str, Any]] | None = None,
) -> Path:
    """Write Cyfrin-format audit report to disk."""
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    report = generate_cyfrin_report(result, hypotheses, platform, findings_data)
    out.write_text(report)
    return out


def write_threat_model(result: AnalysisResult, out: Path) -> Path:
    """Write threat model to disk."""
    from .ai_agent import generate_threat_model

    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    tm = generate_threat_model(result)
    out.write_text(tm)
    return out
