from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class ProposedInvariant(BaseModel):
    id: str
    title: str
    invariant: str
    category: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    related_contracts: list[str] = Field(default_factory=list)
    related_functions: list[str] = Field(default_factory=list)
    related_state: list[str] = Field(default_factory=list)
    why_it_matters: str
    suggested_tests: list[str] = Field(default_factory=list)


class InvariantBreakPlan(BaseModel):
    invariant: str
    likely_attack_classes: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    attack_sequences: list[list[str]] = Field(default_factory=list)
    foundry_test_ideas: list[str] = Field(default_factory=list)
    evidence_to_collect: list[str] = Field(default_factory=list)
    contest_validity_notes: list[str] = Field(default_factory=list)


def load_analysis(path: str | Path) -> dict[str, Any]:
    return json.loads(Path(path).read_text())


def propose_invariants_from_analysis(analysis: dict[str, Any]) -> list[ProposedInvariant]:
    transitions = _extract_transitions(analysis)
    contracts = sorted({t["contract"] for t in transitions if t.get("contract")})
    out: list[ProposedInvariant] = []

    share_fns = [t for t in transitions if _has_any(t, "shares", "totalshares", "deposit", "withdraw", "redeem")]
    reward_fns = [t for t in transitions if _has_any(t, "reward", "rewards", "claim", "emission")]
    asset_fns = [t for t in transitions if _has_any(t, "asset", "transfer", "balance", "withdraw", "deposit")]
    external_call_fns = [t for t in transitions if t.get("external_calls")]

    if share_fns:
        out.append(
            ProposedInvariant(
                id="shares-redeemable",
                title="All shares remain redeemable for their fair asset claim",
                invariant="For all user/action sequences, total redeemable share claims must not exceed vault asset backing.",
                category="vault-accounting",
                confidence=0.74,
                related_contracts=contracts,
                related_functions=_fq_names(share_fns),
                related_state=_state_terms(share_fns),
                why_it_matters="Share/asset drift is the root of donation attacks, inflation attacks, rounding leaks, and insolvency.",
                suggested_tests=[
                    "Fuzz deposit/withdraw/redeem sequences across multiple actors.",
                    "Donate assets directly to the vault between actions.",
                    "Assert share liabilities remain backed by actual token balance.",
                ],
            )
        )

    if reward_fns and asset_fns:
        out.append(
            ProposedInvariant(
                id="rewards-do-not-drain-principal",
                title="Reward claims do not drain principal backing",
                invariant="Reward claims must not make total redeemable shares exceed the remaining asset balance.",
                category="reward-solvency",
                confidence=0.78,
                related_contracts=contracts,
                related_functions=_fq_names(reward_fns),
                related_state=_state_terms(reward_fns),
                why_it_matters="If rewards are paid from the same reserve as user principal, claims can make later withdrawals insolvent.",
                suggested_tests=[
                    "Warp time to accrue maximum rewards.",
                    "Claim rewards as one or more users.",
                    "Assert honest users can still withdraw/redeem their shares.",
                ],
            )
        )

    if external_call_fns:
        out.append(
            ProposedInvariant(
                id="external-calls-do-not-expose-partial-state",
                title="External calls do not expose partially updated accounting",
                invariant="No external callback/reentrant path can observe or exploit partially updated balances, shares, debt, or reward state.",
                category="state-ordering",
                confidence=0.66,
                related_contracts=contracts,
                related_functions=_fq_names(external_call_fns),
                related_state=_state_terms(external_call_fns),
                why_it_matters="External calls around accounting updates are common roots for reentrancy and cross-function state manipulation.",
                suggested_tests=[
                    "Use an attacker contract with fallback/callback hooks.",
                    "Reenter claim/withdraw/deposit paths during token transfer callbacks.",
                    "Assert no user can receive more assets or rewards than entitled.",
                ],
            )
        )

    if asset_fns:
        out.append(
            ProposedInvariant(
                id="actual-assets-match-accounting",
                title="Internal accounting tracks actual token balance changes",
                invariant="State updates for deposits, withdrawals, and rewards must match actual token balance deltas.",
                category="token-accounting",
                confidence=0.70,
                related_contracts=contracts,
                related_functions=_fq_names(asset_fns),
                related_state=_state_terms(asset_fns),
                why_it_matters="Fee-on-transfer, rebasing, callback, and direct-transfer behavior can desync internal accounting from real balances.",
                suggested_tests=[
                    "Use a fee-on-transfer or balance-changing mock token.",
                    "Compare balanceBefore/balanceAfter deltas with accounting updates.",
                    "Assert no user can mint shares or rewards from unreceived assets.",
                ],
            )
        )

    return _dedupe_invariants(out)


def break_invariant_plan(analysis: dict[str, Any], invariant: str) -> InvariantBreakPlan:
    transitions = _extract_transitions(analysis)
    text = invariant.lower()

    likely_attack_classes: list[str] = []
    preconditions: list[str] = []
    attack_sequences: list[list[str]] = []
    foundry_test_ideas: list[str] = []
    evidence_to_collect: list[str] = []
    contest_validity_notes: list[str] = []

    if any(k in text for k in ("share", "redeem", "asset backing", "principal", "solvent", "balance")):
        likely_attack_classes.extend([
            "Donation/share-price manipulation",
            "Fee-on-transfer accounting mismatch",
            "Rounding or zero-share edge case",
        ])
        preconditions.extend([
            "Vault share price can be moved by direct transfers, rounding, or external state.",
            "Deposit/withdraw logic uses nominal amounts or current balances in conversion math.",
        ])
        attack_sequences.extend([
            [
                "Actor A deposits a tiny amount to initialize shares.",
                "Actor A donates assets directly or uses a non-standard token behavior to skew accounting.",
                "Actor B deposits or withdraws at the manipulated conversion rate.",
                "Actor A exits or claims value, then assert victim/protocol loss.",
            ],
            [
                "Create high exchange-rate state through donation or reward accrual.",
                "Try tiny withdraw/redeem amounts around rounding boundaries.",
                "Repeat if profitable and assert cumulative value leakage.",
            ],
        ])
        foundry_test_ideas.extend([
            "test_invariant_allSharesRemainRedeemable_afterDonationAndWithdraw()",
            "test_poc_firstDepositorDonationInflatesSharePrice()",
            "test_poc_feeOnTransferDepositMintsTooManyShares()",
        ])
        evidence_to_collect.extend([
            "Actual token balance before/after each operation.",
            "totalShares/totalSupply before and after each operation.",
            "Per-user share balances and total redeemable assets.",
        ])

    if any(k in text for k in ("reward", "claim", "emission")):
        likely_attack_classes.extend([
            "Reward reserve insolvency",
            "Reward snapshot manipulation",
            "Flash deposit reward capture",
        ])
        preconditions.extend([
            "Rewards are calculated from mutable share/balance state.",
            "Rewards are paid from the same reserve as withdrawal principal or are uncapped.",
        ])
        attack_sequences.append([
            "Actor A deposits or obtains shares.",
            "Warp time or manipulate reward rate/state to accrue rewards.",
            "Actor A claims rewards repeatedly or before checkpointing.",
            "Actor B attempts normal withdrawal; assert whether principal is underfunded.",
        ])
        foundry_test_ideas.extend([
            "test_invariant_rewardClaimsDoNotDrainPrincipal()",
            "test_poc_flashDepositCapturesUnearnedRewards()",
        ])
        evidence_to_collect.extend([
            "Reward liability accrued per user.",
            "Vault asset balance after claims.",
            "Remaining redeemable shares after reward claims.",
        ])

    if any(k in text for k in ("external", "callback", "reentrant", "partial")):
        likely_attack_classes.extend([
            "Single-function reentrancy",
            "Cross-function reentrancy",
            "Read-only reentrancy / stale state observation",
        ])
        preconditions.extend([
            "External call target can be attacker-controlled or token has callbacks/hooks.",
            "Shared accounting state is updated before and after external control is transferred.",
        ])
        attack_sequences.append([
            "Deploy attacker receiver/token with callback.",
            "Trigger the external-call function.",
            "Reenter a related deposit/withdraw/claim path during callback.",
            "Assert double-spend, stale entitlement, or accounting corruption.",
        ])
        foundry_test_ideas.extend([
            "test_poc_reenterClaimDuringTransfer()",
            "test_poc_crossFunctionReentrancyBreaksAccounting()",
        ])
        evidence_to_collect.extend([
            "Storage values immediately before external call.",
            "Storage values during callback.",
            "Final deltas after reentrant sequence.",
        ])

    if not likely_attack_classes:
        likely_attack_classes.append("Generic invariant boundary testing")
        preconditions.append("At least one public/external function can mutate state relevant to the invariant.")
        attack_sequences.append([
            "Identify all functions that read or write invariant-related state.",
            "Try zero, one wei, max, repeated, and multi-actor sequences.",
            "Compare pre/post state to the invariant.",
        ])
        foundry_test_ideas.append("test_invariant_customInvariantCannotBeBroken()")
        evidence_to_collect.append("All state variables referenced by the invariant before and after each sequence.")

    contest_validity_notes.extend([
        "Escalate only if the broken invariant produces realistic fund loss, insolvency, reward theft, or permanent DoS.",
        "Downgrade or discard if the path requires trusted admin misuse and contest rules trust admins.",
        "Treat weird-token behavior as contest-dependent unless the protocol claims arbitrary ERC20 support or the token is in scope.",
    ])

    return InvariantBreakPlan(
        invariant=invariant,
        likely_attack_classes=_unique(likely_attack_classes),
        preconditions=_unique(preconditions),
        attack_sequences=_dedupe_sequences(attack_sequences),
        foundry_test_ideas=_unique(foundry_test_ideas),
        evidence_to_collect=_unique(evidence_to_collect),
        contest_validity_notes=_unique(contest_validity_notes),
    )


def invariants_to_markdown(invariants: list[ProposedInvariant]) -> str:
    lines = ["# Proposed Invariants", ""]
    for idx, inv in enumerate(invariants, start=1):
        lines.extend([
            f"## {idx}. {inv.title}",
            "",
            f"- **ID:** `{inv.id}`",
            f"- **Category:** {inv.category}",
            f"- **Confidence:** {inv.confidence:.2f}",
            f"- **Contracts:** {', '.join(inv.related_contracts) if inv.related_contracts else 'n/a'}",
            f"- **Functions:** {', '.join(inv.related_functions) if inv.related_functions else 'n/a'}",
            "",
            "### Invariant",
            inv.invariant,
            "",
            "### Why it matters",
            inv.why_it_matters,
            "",
            "### Suggested tests",
        ])
        lines.extend([f"- {test}" for test in inv.suggested_tests])
        lines.append("")
    return "\n".join(lines)


def break_plan_to_markdown(plan: InvariantBreakPlan) -> str:
    lines = [
        "# Invariant Break Plan",
        "",
        "## Invariant",
        plan.invariant,
        "",
        "## Likely attack classes",
    ]
    lines.extend([f"- {item}" for item in plan.likely_attack_classes])
    lines.extend(["", "## Preconditions"])
    lines.extend([f"- {item}" for item in plan.preconditions])
    lines.extend(["", "## Attack sequences"])
    for idx, seq in enumerate(plan.attack_sequences, start=1):
        lines.append(f"### Sequence {idx}")
        lines.extend([f"{step_idx}. {step}" for step_idx, step in enumerate(seq, start=1)])
    lines.extend(["", "## Foundry test ideas"])
    lines.extend([f"- `{item}`" for item in plan.foundry_test_ideas])
    lines.extend(["", "## Evidence to collect"])
    lines.extend([f"- {item}" for item in plan.evidence_to_collect])
    lines.extend(["", "## Contest-validity notes"])
    lines.extend([f"- {item}" for item in plan.contest_validity_notes])
    lines.append("")
    return "\n".join(lines)


def _extract_transitions(analysis: dict[str, Any]) -> list[dict[str, Any]]:
    raw = analysis.get("transitions", [])
    if not isinstance(raw, list):
        return []

    out: list[dict[str, Any]] = []
    for item in raw:
        if hasattr(item, "model_dump"):
            item = item.model_dump()
        if isinstance(item, dict):
            out.append(item)
    return out


def _fq_names(transitions: list[dict[str, Any]]) -> list[str]:
    names = []
    for t in transitions:
        contract = t.get("contract") or t.get("contract_name") or "UnknownContract"
        function = t.get("function") or t.get("name") or "unknown"
        names.append(f"{contract}.{function}")
    return sorted(set(names))


def _state_terms(transitions: list[dict[str, Any]]) -> list[str]:
    terms: list[str] = []
    for t in transitions:
        for key in ("reads_storage", "writes_storage", "reads", "writes"):
            value = t.get(key, [])
            if isinstance(value, list):
                terms.extend(str(v) for v in value)
    return sorted(set(terms))


def _has_any(transition: dict[str, Any], *needles: str) -> bool:
    haystack_parts = []
    for key in (
        "contract",
        "contract_name",
        "function",
        "name",
        "reads_storage",
        "writes_storage",
        "external_calls",
        "asset_movements",
    ):
        value = transition.get(key, "")
        if isinstance(value, list):
            haystack_parts.extend(str(v) for v in value)
        else:
            haystack_parts.append(str(value))
    haystack = " ".join(haystack_parts).lower()
    return any(needle.lower() in haystack for needle in needles)


def _dedupe_invariants(invariants: list[ProposedInvariant]) -> list[ProposedInvariant]:
    seen = set()
    out = []
    for inv in sorted(invariants, key=lambda item: item.confidence, reverse=True):
        if inv.id in seen:
            continue
        seen.add(inv.id)
        out.append(inv)
    return out


def _unique(items: list[str]) -> list[str]:
    return list(dict.fromkeys(items))


def _dedupe_sequences(sequences: list[list[str]]) -> list[list[str]]:
    seen = set()
    out = []
    for seq in sequences:
        key = tuple(seq)
        if key in seen:
            continue
        seen.add(key)
        out.append(seq)
    return out
