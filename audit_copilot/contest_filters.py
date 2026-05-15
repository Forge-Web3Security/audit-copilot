from __future__ import annotations

from .models import ExploitabilityAssessment, FindingCandidate, InvariantCandidate, Platform, ScannerSignal, StateTransition

INVALID_KEYWORDS = {
    "admin-only intended behavior": ["onlyowner", "onlyadmin", "owner", "admin", "governor", "onlyrole"],
    "gas-only/no material loss": ["gas", "optimization"],
    "zero-address validation only": ["zero address", "address(0)"],
    "theoretical without exploit path": ["theoretical", "informational"],
    "oracle-only issue may be out of scope": ["oracle", "stale price", "price feed"],
}

PLATFORM_STYLE = {
    Platform.sherlock: "Prioritize practical exploitability, realistic call sequence, material loss, and scope validity.",
    Platform.code4rena: "Prioritize clear root cause, impact breadth, reproducibility, and duplicate-resistant framing.",
    Platform.codehawks: "Prioritize correctness bugs with crisp proof and simple reproduction.",
    Platform.immunefi: "Prioritize direct fund loss, severity proof, and concrete exploit path.",
    Platform.generic: "Prioritize realistic impact and reproducible proof.",
}


def assess_transition(t: StateTransition) -> ExploitabilityAssessment:
    invalid = []
    notes = []
    auth_text = " ".join(t.auth_requirements).lower()
    if auth_text and any(k in auth_text for k in INVALID_KEYWORDS["admin-only intended behavior"]):
        invalid.append("admin-only intended behavior unless authorization bypass exists")
    if t.asset_movements and not invalid:
        return ExploitabilityAssessment(
            realistic=True,
            profitable=True,
            permissionless=not bool(t.auth_requirements),
            repeatable=True,
            impact_material=True,
            invalid_reasons=invalid,
            notes=t.notes + notes,
        )
    return ExploitabilityAssessment(
        realistic=bool(t.external_calls or t.timing_dependencies or t.writes_storage),
        profitable=bool(t.asset_movements),
        permissionless=not bool(t.auth_requirements),
        repeatable=False,
        impact_material=bool(t.asset_movements),
        invalid_reasons=invalid,
        notes=t.notes + notes,
    )


def generate_findings(platform: Platform, transitions: list[StateTransition], invariants: list[InvariantCandidate], signals: list[ScannerSignal]) -> list[FindingCandidate]:
    findings: list[FindingCandidate] = []
    idx = 1

    for t in transitions:
        interesting = t.asset_movements or t.external_calls or t.timing_dependencies or t.notes
        if not interesting:
            continue
        assessment = assess_transition(t)
        sev = "high" if assessment.likely_valid and t.asset_movements else "medium" if assessment.realistic else "informational"
        related_inv = [i.id for i in invariants if t.contract in i.related_contracts or f"{t.contract}.{t.function}" in i.related_functions]
        findings.append(FindingCandidate(
            id=f"F-{idx:03d}",
            title=f"Review {t.contract}.{t.function} for invariant break or exploitable state transition",
            hypothesis=f"{t.contract}.{t.function} touches {', '.join(t.asset_movements or t.external_calls or t.timing_dependencies)}. Validate whether call ordering, stale state, or missing authorization can break protocol invariants.",
            source="state-transition-analysis",
            related_invariants=related_inv,
            related_transitions=[f"{t.contract}.{t.function}"],
            assessment=assessment,
            severity_guess=sev,
            next_validation_steps=[
                PLATFORM_STYLE[platform],
                "Write the minimal Foundry PoC sequence: setup → manipulate state → trigger vulnerable transition → assert profit/loss.",
                "Check whether assumptions are out of scope: admin action, malicious token, external oracle/integration, or no material loss.",
            ],
        ))
        idx += 1

    for s in signals:
        text = f"{s.check} {s.title} {s.description}".lower()
        invalid = []
        for reason, keys in INVALID_KEYWORDS.items():
            if any(k in text for k in keys):
                invalid.append(reason)
        material = any(k in text for k in ["reentrancy", "arbitrary", "unchecked", "delegatecall", "selfdestruct", "price", "withdraw", "transfer"])
        findings.append(FindingCandidate(
            id=f"F-{idx:03d}",
            title=f"Triage scanner signal: {s.title}",
            hypothesis="Scanner signal requires manual exploitability validation before reporting.",
            source=s.tool,
            related_signals=[s],
            assessment=ExploitabilityAssessment(
                realistic=material,
                profitable=material,
                permissionless=False,
                repeatable=False,
                impact_material=material,
                invalid_reasons=invalid,
                notes=["Do not report raw scanner output without a realistic exploit path."],
            ),
            severity_guess="medium" if material and not invalid else "informational",
            next_validation_steps=[
                "Map this signal to protocol invariant failure, not just a code smell.",
                "Prove attacker permissions and repeatability.",
                "Discard if it is only best-practice, gas-only, admin-only, or no-loss.",
            ],
        ))
        idx += 1

    return findings
