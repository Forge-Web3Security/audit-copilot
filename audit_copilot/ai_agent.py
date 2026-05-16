from __future__ import annotations

from typing import Any

from .models import AnalysisResult
from .analysis.hypothesis_engine import Hypothesis


def generate_agent_prompt(result: AnalysisResult, hypotheses: list[Hypothesis], platform: str = "sherlock") -> str:
    """Generate a structured AI agent prompt from analysis results.
    
    The prompt guides an LLM agent (Claude, GPT, etc.) through the audit process:
    1. Review hypotheses and assess exploitability
    2. Write Foundry PoC tests
    3. Determine severity per platform rules
    4. Generate findings in Cyfrin format
    """
    contracts_summary = "\n".join(
        f"- {c.name} ({c.path})"
        for c in result.model.contracts
    ) or "- None detected"

    transitions_summary = "\n".join(
        f"- {t.contract}.{t.function}: writes={t.writes_storage}, calls={t.external_calls}, auth={t.auth_requirements}"
        for t in result.transitions[:20]
    ) or "- None detected"

    invariants_summary = "\n".join(
        f"- **{i.id}**: {i.title} ({i.category})"
        for i in result.invariants
    ) or "- None generated"

    hypotheses_summary = "\n".join(
        f"- **{h.id}** ({h.severity_guess}, confidence={h.confidence:.2f}): {h.title}"
        for h in hypotheses
    ) or "- None generated"

    platform_rules = {
        "sherlock": (
            "Sherlock rules:\n"
            "- High: loss of funds, broken protocol invariant, permanent DoS\n"
            "- Medium: indirect loss, temporary DoS, MEV, accounting edge cases\n"
            "- Admin trust is assumed — admin-only issues are invalid unless there's a privilege escalation\n"
            "- Oracle issues are in scope only if the protocol misuses oracle data, not if the oracle itself fails"
        ),
        "code4rena": (
            "Code4rena rules:\n"
            "- High: direct loss of funds, broken core invariant, malicious input can steal value\n"
            "- Medium: loss under specific conditions, MEV, front-running, temporary DoS\n"
            "- Low: informational, code quality, missing events\n"
            "- Duplicate detection is strict — focus on unique root causes"
        ),
        "codehawks": (
            "CodeHawks rules:\n"
            "- High: direct loss of funds, broken invariant, permanent DoS\n"
            "- Medium: indirect loss, MEV, edge cases\n"
            "- Low: best practices, gas\n"
            "- Focus on correctness bugs with minimal, reproducible proofs"
        ),
        "immunefi": (
            "Immunefi rules:\n"
            "- Critical: direct loss of user funds without requiring special permissions\n"
            "- High: direct loss requiring specific conditions or permissions\n"
            "- Medium: indirect loss, MEV, temporary DoS\n"
            "- Bounties require provable exploit paths demonstrated on mainnet fork"
        ),
        "generic": (
            "Generic audit rules:\n"
            "- Prioritize realistic, provable exploit paths\n"
            "- Document trust assumptions and contest scope\n"
            "- Provide Foundry PoC for every finding"
        ),
    }

    return f"""You are an expert smart contract security auditor.

## Protocol Model

Contracts:
{contracts_summary}

Actors: {', '.join(result.model.actors)}
Privileged roles: {', '.join(result.model.privileged_roles)}
Assets: {', '.join(result.model.assets)}
Integrations: {', '.join(result.model.integrations)}

## State Transitions

{transitions_summary}

## Invariants

{invariants_summary}

## Platform Context

Auditing for: **{platform.upper()}**
{platform_rules.get(platform, platform_rules["generic"])}

## Candidate Hypotheses to Investigate

{hypotheses_summary}

## Your Tasks

### Task 1: Assess Each Hypothesis
For each hypothesis above, determine:
- Is it realistically exploitable? (yes/no)
- What are the exact preconditions?
- Can you write a Foundry PoC?

### Task 2: Write Foundry PoC
For confirmed hypotheses, write a Foundry test:
1. Deploy protocol contracts and configure initial state
2. Set up attacker/victim actors
3. Execute the exploit sequence
4. Assert material impact (profit, loss, invariant break)

### Task 3: Assign Platform Severity
Map each confirmed finding to platform-specific severity:
- High/Critical: direct fund loss, broken invariant, permanent DoS
- Medium: indirect loss, MEV, edge case
- Low/Informational: best practice, gas

### Task 4: Generate Cyfrin-Format Report Finding

Use this template for each finding:

```markdown
### [Severity] Finding Title (ROOT CAUSE + IMPACT)

**Description:**
Clear explanation of the vulnerability and root cause.

**Impact:**
What an attacker can accomplish.

**Proof of Concept:**
```solidity
// Foundry test demonstrating the exploit
```

**Recommended Mitigation:**
Specific fix or code change.

**Contest Validity:**
Why this finding is valid under {platform.upper()} rules.
```
"""


def generate_threat_model(result: AnalysisResult) -> str:
    """Generate a Cyfrin-format threat model from analysis results."""
    contracts_list = "\n".join(
        f"| {c.name} | {c.path} | {', '.join(c.inherits) if c.inherits else '-'} |"
        for c in result.model.contracts
    ) or "| - | - | - |"

    trust_assumptions = "\n".join(
        f"- {t}" for t in result.model.trust_assumptions
    ) or "- None documented"

    econ_primitives = "\n".join(
        f"- **{e.name}**: sources={e.source_of_value}, sinks={e.sink_of_value}"
        for e in result.model.economic_primitives
    ) or "- None detected"

    return f"""# Threat Model

## Protocol Summary

- **Root:** {result.model.root}
- **Platform mode:** {result.platform.value}
- **Contracts:** {len(result.model.contracts)}

## Actors & Roles

| Role | Type |
|---|---|
{'|'.join(f' {a} | ' + ('Privileged' if a in result.model.privileged_roles else 'External') + ' |' for a in result.model.actors)}

## Contracts

| Contract | Path | Inherits |
|---|---|---|
{contracts_list}

## Assets

{', '.join(result.model.assets) if result.model.assets else 'None detected'}

## Integrations

{', '.join(result.model.integrations) if result.model.integrations else 'None detected'}

## Trust Assumptions

{trust_assumptions}

## Economic Primitives

{econ_primitives}

## Core Invariants

{chr(10).join(f'- **{i.id}**: {i.title}' for i in result.invariants) if result.invariants else '- None identified'}

## Privileged Roles

{', '.join(result.model.privileged_roles) if result.model.privileged_roles else 'None detected'}
"""


def hypotheses_to_findings(hypotheses: list[Hypothesis], analysis: dict[str, Any]) -> list[dict[str, Any]]:
    """Convert hypotheses into structured Cyfrin-format findings for the final audit report."""
    findings: list[dict[str, Any]] = []

    for h in hypotheses:
        finding = {
            "id": h.id,
            "title": h.title,
            "severity": h.severity_guess,
            "confidence": h.confidence,
            "description": _build_description(h),
            "impact": _build_impact(h),
            "proof_of_concept": _build_poc_steps(h),
            "recommended_mitigation": _build_mitigation(h),
            "affected_contracts": h.affected_contracts,
            "affected_functions": h.related_functions,
            "tags": h.tags,
            "contest_validity": h.contest_validity_notes,
        }
        findings.append(finding)

    return findings


def _build_description(h: Hypothesis) -> str:
    return f"{h.title}. Invariant: {h.invariant}. " + " ".join(h.evidence)


def _build_impact(h: Hypothesis) -> str:
    if any(t in h.tags for t in ("high", "critical")):
        return "Direct loss of funds, broken protocol invariant, or permanent denial of service."
    if "medium" in h.tags or h.severity_guess in ("medium", "high"):
        return "Indirect loss of funds under specific conditions or temporary denial of service."
    return "Informational code quality or best-practice issue."


def _build_poc_steps(h: Hypothesis) -> list[str]:
    return h.exploit_sketch or ["No exploit sketch available."]


def _build_mitigation(h: Hypothesis) -> str:
    return "Apply the invariant: " + h.invariant
