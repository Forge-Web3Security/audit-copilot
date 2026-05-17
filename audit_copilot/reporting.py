from __future__ import annotations

import json
from pathlib import Path
from .models import AnalysisResult, FindingCandidate


def write_json(result: AnalysisResult, out: Path) -> None:
    (out / "analysis.json").write_text(result.model_dump_json(indent=2), encoding="utf-8")


def finding_section(f: FindingCandidate) -> str:
    invalid = "\n".join([f"- {r}" for r in f.assessment.invalid_reasons]) or "- None detected yet"
    steps = "\n".join([f"- {s}" for s in f.next_validation_steps])
    inv = ", ".join(f.related_invariants) or "None mapped yet"
    return f"""
## {f.id}: {f.title}

**Severity guess:** {f.severity_guess}  
**Source:** {f.source}  
**Related invariants:** {inv}

### Hypothesis

{f.hypothesis}

### Exploitability checklist

| Criterion | Current value |
|---|---:|
| Realistic | {f.assessment.realistic} |
| Profitable | {f.assessment.profitable} |
| Permissionless | {f.assessment.permissionless} |
| Repeatable | {f.assessment.repeatable} |
| Material impact | {f.assessment.impact_material} |

### Invalidity filters hit

{invalid}

### Next validation steps

{steps}
"""


def write_markdown(result: AnalysisResult, out: Path) -> None:
    model = result.model
    contracts = "\n".join([f"- `{c.name}` — `{c.path}`" for c in model.contracts]) or "- None found"
    roles = ", ".join(model.privileged_roles) or "None detected"
    assets = ", ".join(model.assets) or "None detected"
    integrations = ", ".join(model.integrations) or "None detected"
    invariants = "\n".join([f"- **{i.id}: {i.title}** — {i.description}" for i in result.invariants])
    findings = "\n".join(finding_section(f) for f in result.findings[:50]) or "No candidates generated."

    md = f"""# Audit Copilot Analysis

Platform mode: **{result.platform.value}**

## Protocol model

### Contracts

{contracts}

### Privileged roles

{roles}

### Assets

{assets}

### Integrations

{integrations}

### Trust assumptions

{chr(10).join([f'- {x}' for x in model.trust_assumptions]) or '- None detected'}

## Candidate invariants

{invariants}

## Finding candidates

{findings}

## Reminder

Do not submit candidates directly. Promote only findings with a realistic exploit sequence, valid scope, and material impact.
"""
    (out / "report.md").write_text(md, encoding="utf-8")
