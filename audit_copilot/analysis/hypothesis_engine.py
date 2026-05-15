"""Generate exploit-oriented audit hypotheses from protocol analysis output.

The goal of this module is not to prove vulnerabilities. It turns extracted
facts into contest-ready questions worth investigating, with invariants,
preconditions, exploit sketches, validation steps, and contest-validity notes.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any, Literal

from pydantic import BaseModel, Field


SeverityGuess = Literal["info", "low", "medium", "high"]


class Hypothesis(BaseModel):
    """A potential finding candidate produced by heuristic reasoning."""

    id: str
    title: str
    severity_guess: SeverityGuess = "medium"
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    affected_contracts: list[str] = Field(default_factory=list)
    related_functions: list[str] = Field(default_factory=list)
    related_state: list[str] = Field(default_factory=list)
    invariant: str
    attack_preconditions: list[str] = Field(default_factory=list)
    exploit_sketch: list[str] = Field(default_factory=list)
    validation_steps: list[str] = Field(default_factory=list)
    contest_validity_notes: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class FunctionSignal(BaseModel):
    contract: str = "UnknownContract"
    name: str = "unknown"
    visibility: str | None = None
    modifiers: list[str] = Field(default_factory=list)
    reads: list[str] = Field(default_factory=list)
    writes: list[str] = Field(default_factory=list)
    external_calls: list[str] = Field(default_factory=list)
    asset_movements: list[str] = Field(default_factory=list)
    authorization_hints: list[str] = Field(default_factory=list)
    body: str = ""
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def fq_name(self) -> str:
        return f"{self.contract}.{self.name}"

    @property
    def is_public_entrypoint(self) -> bool:
        return self.visibility in {"public", "external", None}

    @property
    def has_external_call(self) -> bool:
        return bool(self.external_calls)

    @property
    def has_asset_movement(self) -> bool:
        joined = _joined(self.asset_movements + self.external_calls + [self.name, self.body])
        return any(
            keyword in joined
            for keyword in (
                "transfer",
                "transferfrom",
                "safetransfer",
                "safetransferfrom",
                "send",
                "call{value",
                ".call",
                "mint",
                "burn",
                "deposit",
                "withdraw",
                "redeem",
                "claim",
            )
        )

    @property
    def has_auth(self) -> bool:
        joined = _joined(self.modifiers + self.authorization_hints)
        return any(
            keyword in joined
            for keyword in (
                "onlyowner",
                "onlyrole",
                "admin",
                "auth",
                "governance",
                "manager",
                "keeper",
            )
        )

    @property
    def state_blob(self) -> str:
        return _joined(self.reads + self.writes + [self.body, self.name])


class HypothesisEngine:
    """Rule-based exploit hypothesis generator."""

    def generate(self, analysis: Mapping[str, Any]) -> list[Hypothesis]:
        functions = _extract_functions(analysis)
        hypotheses: list[Hypothesis] = []

        hypotheses.extend(self._external_call_state_ordering(functions))
        hypotheses.extend(self._accounting_without_asset_movement(functions))
        hypotheses.extend(self._asset_movement_without_auth(functions))
        hypotheses.extend(self._reward_snapshot_or_stale_balance(functions))
        hypotheses.extend(self._oracle_or_price_manipulation(functions))
        hypotheses.extend(self._share_or_erc4626_manipulation(functions))
        hypotheses.extend(self._liquidation_debt_drift(functions))
        hypotheses.extend(self._pause_or_admin_centralization(functions))

        return _rank_hypotheses(_precision_filter(_dedupe_hypotheses(hypotheses)))

    def _external_call_state_ordering(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            if not fn.is_public_entrypoint or not fn.has_external_call or not fn.writes:
                continue
            joined_calls = _joined(fn.external_calls + [fn.body])
            if not any(k in joined_calls for k in ("call", "transfer", "safe", "onerc", "callback", "hook")):
                continue
            out.append(
                Hypothesis(
                    id=_hid("external-call-order", fn.fq_name),
                    title="External call may occur in a state-changing entrypoint",
                    severity_guess="high" if fn.has_asset_movement else "medium",
                    confidence=0.66,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=fn.writes,
                    invariant="State transitions that affect balances, debt, shares, or rewards should be finalized before untrusted external control is transferred.",
                    attack_preconditions=[
                        "The external call target can be attacker-controlled or can trigger a callback.",
                        "The function can be re-entered or composed with another state-dependent action before accounting is finalized.",
                    ],
                    exploit_sketch=[
                        f"Call {fn.fq_name} through an attacker-controlled contract.",
                        "Use the callback/reentrant path to observe stale or partially-updated state.",
                        "Repeat or compose actions to drain value, bypass checks, or corrupt accounting.",
                    ],
                    validation_steps=[
                        "Inspect exact ordering of storage writes versus external calls in the Solidity body.",
                        "Write a Foundry attacker contract with fallback/callback hooks.",
                        "Assert whether balances, shares, debt, or rewards can change twice from one logical action.",
                    ],
                    contest_validity_notes=[
                        "Valid only if it creates realistic fund loss, insolvency, reward theft, or privilege bypass.",
                        "Do not report as a generic CEI best-practice issue without a concrete exploit path.",
                    ],
                    evidence=[f"writes={fn.writes}", f"external_calls={fn.external_calls}"],
                    tags=["reentrancy", "state-ordering", "external-call"],
                )
            )
        return out

    def _accounting_without_asset_movement(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            looks_accounting = any(k in fn.state_blob for k in _ACCOUNTING_TERMS)
            if not fn.is_public_entrypoint or not looks_accounting or fn.has_asset_movement:
                continue
            out.append(
                Hypothesis(
                    id=_hid("accounting-no-assets", fn.fq_name),
                    title="Accounting state may change without matching asset movement",
                    severity_guess="high" if not fn.has_auth else "medium",
                    confidence=0.60 if not fn.has_auth else 0.42,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=fn.writes,
                    invariant="Internal accounting changes should correspond to equivalent token movement, debt realization, or explicitly documented virtual accounting.",
                    attack_preconditions=[
                        "The function is reachable by an untrusted or weakly trusted actor.",
                        "The written accounting state influences withdrawals, claims, borrowing power, or liquidation.",
                    ],
                    exploit_sketch=[
                        f"Invoke {fn.fq_name} to mutate accounting without transferring assets.",
                        "Use the inflated/deflated accounting state in a later redeem, claim, borrow, or liquidation path.",
                    ],
                    validation_steps=[
                        "Trace whether token balances actually change in the same transaction.",
                        "Compare internal accounting against ERC20 balanceOf before and after the call.",
                        "Build an invariant: protocol assets >= user/accounting liabilities.",
                    ],
                    contest_validity_notes=[
                        "Strong candidate if permissionless and value-bearing.",
                        "Likely invalid if only an authorized/admin bookkeeping action and admins are trusted by contest rules.",
                    ],
                    evidence=[f"reads={fn.reads}", f"writes={fn.writes}"],
                    tags=["accounting", "assets-liabilities", "invariant"],
                )
            )
        return out

    def _asset_movement_without_auth(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            if not fn.is_public_entrypoint or not fn.has_asset_movement or fn.has_auth:
                continue
            name = fn.name.lower()
            dangerous = any(k in name for k in ("sweep", "rescue", "withdraw", "claim", "mint", "burn", "refund", "payout"))
            if not dangerous:
                continue
            out.append(
                Hypothesis(
                    id=_hid("asset-move-no-auth", fn.fq_name),
                    title="Value-moving function appears externally reachable without strong authorization",
                    severity_guess="high",
                    confidence=0.70,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=fn.writes,
                    invariant="Only the rightful owner of value or an authorized protocol role should be able to move protocol/user assets.",
                    attack_preconditions=[
                        "The function can move assets belonging to the protocol or other users.",
                        "Caller identity, ownership, entitlement, or role checks are missing or bypassable.",
                    ],
                    exploit_sketch=[
                        f"Call {fn.fq_name} as an arbitrary user.",
                        "Choose parameters that route funds, shares, refunds, or rewards to the attacker.",
                    ],
                    validation_steps=[
                        "Confirm whether msg.sender ownership/entitlement is enforced.",
                        "Create a two-user Foundry test where attacker moves victim/protocol value.",
                    ],
                    contest_validity_notes=[
                        "Usually valid when arbitrary users can take funds or rewards they did not earn.",
                        "Avoid reporting if the moved asset is intentionally permissionless and no user/protocol loss occurs.",
                    ],
                    evidence=[f"visibility={fn.visibility}", f"modifiers={fn.modifiers}", f"asset_movements={fn.asset_movements}"],
                    tags=["access-control", "asset-loss"],
                )
            )
        return out

    def _reward_snapshot_or_stale_balance(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            blob = fn.state_blob
            if not any(k in blob for k in _REWARD_TERMS):
                continue
            if not any(k in blob for k in ("claim", "reward", "lastclaim", "checkpoint", "shares", "balance", "timestamp")):
                continue
            out.append(
                Hypothesis(
                    id=_hid("reward-snapshot", fn.fq_name),
                    title="Reward accounting may rely on stale snapshots or manipulable balances",
                    severity_guess="medium",
                    confidence=0.55,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=[s for s in fn.reads + fn.writes if any(t in s.lower() for t in _REWARD_TERMS)],
                    invariant="Rewards should be distributed according to time-weighted or checkpointed entitlement, not flash-inflated balances.",
                    attack_preconditions=[
                        "Rewards are calculated from a balance/share value that can change shortly before claiming.",
                        "There is no robust checkpoint before balance changes or reward accrual.",
                    ],
                    exploit_sketch=[
                        "Acquire or inflate balance immediately before reward calculation.",
                        f"Call {fn.fq_name} to claim using the manipulated entitlement.",
                        "Exit the position after extracting outsized rewards.",
                    ],
                    validation_steps=[
                        "Simulate deposit/transfer immediately before claim.",
                        "Compare attacker reward against a long-term honest holder.",
                    ],
                    contest_validity_notes=[
                        "Valid if rewards have real value and the attacker extracts unearned emissions.",
                        "Out-of-design or dust-only reward loss may be invalid depending on contest rules.",
                    ],
                    evidence=[f"reward_related_state={[s for s in fn.reads + fn.writes if any(t in s.lower() for t in _REWARD_TERMS)]}"],
                    tags=["rewards", "snapshot", "economic"],
                )
            )
        return out

    def _oracle_or_price_manipulation(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            blob = fn.state_blob + _joined(fn.external_calls)
            has_price_evidence = any(k in blob for k in _PRICE_TERMS)
            has_value_conversion = any(k in blob for k in ("mint", "redeem", "borrow", "liquidat", "collateral", "convert", "amountout", "shares"))
            if not has_price_evidence or not has_value_conversion:
                continue
            out.append(
                Hypothesis(
                    id=_hid("price-manipulation", fn.fq_name),
                    title="Price-dependent path may be vulnerable to stale or manipulable valuation",
                    severity_guess="high",
                    confidence=0.58,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=fn.reads,
                    invariant="Minting, redemption, borrowing, liquidation, and collateral valuation should use fresh and manipulation-resistant prices.",
                    attack_preconditions=[
                        "The price source can be stale, thinly liquid, same-block manipulable, or missing bounds.",
                        "The function converts price error into minting, borrowing, redemption, or liquidation profit.",
                    ],
                    exploit_sketch=[
                        "Manipulate or wait for a stale valuation source.",
                        f"Call {fn.fq_name} while the protocol accepts the bad price.",
                        "Extract profit through over-minting, underpaying, unfair liquidation, or redeeming at a false rate.",
                    ],
                    validation_steps=[
                        "Identify the exact oracle source and freshness/bounds checks.",
                        "Fork-test with mocked oracle values or pool skew.",
                        "Quantify profit after fees, slippage, and required capital.",
                    ],
                    contest_validity_notes=[
                        "Generic missing stale checks can be invalid in some contests unless tied to concrete loss.",
                        "Oracle/provider malfunction itself is often out of scope; protocol misuse of oracle data may still be valid.",
                    ],
                    evidence=[f"reads={fn.reads}", f"external_calls={fn.external_calls}"],
                    tags=["oracle", "price", "economic"],
                )
            )
        return out

    def _share_or_erc4626_manipulation(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            blob = fn.state_blob
            share_related = any(k in blob for k in _SHARE_TERMS)
            conversion_like = any(k in fn.name.lower() for k in ("deposit", "withdraw", "mint", "redeem")) or any(k in blob for k in ("totalshares", "totalassets", "balanceof", "convertto"))
            if not share_related or not conversion_like:
                continue
            out.append(
                Hypothesis(
                    id=_hid("share-manipulation", fn.fq_name),
                    title="Share/asset conversion may be manipulable by donation, rounding, or first-depositor effects",
                    severity_guess="high",
                    confidence=0.62,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=[s for s in fn.reads + fn.writes if any(t in s.lower() for t in _SHARE_TERMS)],
                    invariant="Share minting and redemption should preserve proportional ownership across deposits, withdrawals, donations, and rounding boundaries.",
                    attack_preconditions=[
                        "Conversion uses current token balance or totalAssets that can be externally changed.",
                        "Rounding favors one side enough to create repeatable or first-depositor profit.",
                    ],
                    exploit_sketch=[
                        "Initialize or skew share price with a tiny deposit and/or direct donation.",
                        f"Use {fn.fq_name} or paired mint/redeem paths at the manipulated conversion rate.",
                        "Extract value from later depositors or from protocol-held assets.",
                    ],
                    validation_steps=[
                        "Test first deposit, zero supply, tiny amount, and direct token donation cases.",
                        "Fuzz deposit/redeem round trips and assert no profitable cycle beyond expected dust.",
                    ],
                    contest_validity_notes=[
                        "Donation/rounding issues are strong when they steal from later users or create protocol insolvency.",
                        "Pure dust loss or user self-harm may be invalid.",
                    ],
                    evidence=[f"share_related_state={[s for s in fn.reads + fn.writes if any(t in s.lower() for t in _SHARE_TERMS)]}"],
                    tags=["shares", "erc4626", "rounding", "donation"],
                )
            )
        return out

    def _liquidation_debt_drift(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            blob = fn.state_blob
            if "liquidat" not in blob and "debt" not in blob:
                continue
            out.append(
                Hypothesis(
                    id=_hid("debt-liquidation-drift", fn.fq_name),
                    title="Debt/collateral accounting may drift across liquidation or repayment paths",
                    severity_guess="high",
                    confidence=0.57,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=fn.reads + fn.writes,
                    invariant="Debt, collateral, and liquidation settlement should remain solvent and internally consistent across partial repay/liquidation sequences.",
                    attack_preconditions=[
                        "Debt or collateral can be partially updated, rounded, or settled through multiple paths.",
                        "The attacker can choose ordering, amount, or liquidation timing.",
                    ],
                    exploit_sketch=[
                        "Create a position near a boundary.",
                        f"Use {fn.fq_name} with partial amounts or manipulated timing.",
                        "Check whether bad debt, excess collateral, or unfair liquidation profit appears.",
                    ],
                    validation_steps=[
                        "Fuzz partial repay/liquidation amounts and boundary collateral ratios.",
                        "Assert protocol assets plus debt claims remain solvent.",
                    ],
                    contest_validity_notes=["Strong if it creates bad debt or lets users escape liabilities."],
                    evidence=[f"reads={fn.reads}", f"writes={fn.writes}"],
                    tags=["liquidation", "debt", "solvency"],
                )
            )
        return out

    def _pause_or_admin_centralization(self, functions: list[FunctionSignal]) -> list[Hypothesis]:
        out: list[Hypothesis] = []
        for fn in functions:
            if not fn.has_auth:
                continue
            blob = fn.state_blob
            if not any(k in blob for k in ("owner", "admin", "role", "pause", "upgrade", "rate", "fee", "oracle", "reward")):
                continue
            out.append(
                Hypothesis(
                    id=_hid("privilege-review", fn.fq_name),
                    title="Privileged control path should be reviewed against contest trust assumptions",
                    severity_guess="medium",
                    confidence=0.45,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=fn.writes,
                    invariant="Trusted roles should not be able to violate protocol guarantees unless the contest explicitly accepts that trust assumption.",
                    attack_preconditions=[
                        "The role is compromised, misconfigured, or unexpectedly reachable by non-admin users.",
                        "The action can affect user funds, pricing, withdrawals, or upgrades.",
                    ],
                    exploit_sketch=[
                        f"Map which role can call {fn.fq_name}.",
                        "Check whether role assignment, initialization, or upgrade paths can be abused by non-admins.",
                    ],
                    validation_steps=[
                        "Check deployment initialization and role grant/revoke flows.",
                        "Separate true access-control bugs from trusted-admin design decisions.",
                    ],
                    contest_validity_notes=[
                        "Admin misuse is usually invalid where admins are trusted.",
                        "Valid only if a non-admin can gain privilege or if docs restrict the privileged action.",
                    ],
                    evidence=[f"modifiers={fn.modifiers}", f"writes={fn.writes}"],
                    tags=["privilege", "contest-validity"],
                )
            )
        return out


def generate_hypotheses(analysis: Mapping[str, Any]) -> list[Hypothesis]:
    return HypothesisEngine().generate(analysis)


def hypotheses_to_markdown(hypotheses: list[Hypothesis]) -> str:
    lines = ["# Finding Hypotheses", ""]
    if not hypotheses:
        lines.extend(["No hypotheses generated.", ""])
        return "\n".join(lines)

    for idx, h in enumerate(hypotheses, start=1):
        lines.extend(
            [
                f"## {idx}. {h.title}",
                "",
                f"- **ID:** `{h.id}`",
                f"- **Severity guess:** {h.severity_guess}",
                f"- **Confidence:** {h.confidence:.2f}",
                f"- **Contracts:** {', '.join(h.affected_contracts) or 'n/a'}",
                f"- **Functions:** {', '.join(h.related_functions) or 'n/a'}",
                f"- **Tags:** {', '.join(h.tags) or 'n/a'}",
                "",
                "### Candidate invariant",
                h.invariant,
                "",
            ]
        )
        _md_list(lines, "Attack preconditions", h.attack_preconditions)
        _md_list(lines, "Exploit sketch", h.exploit_sketch, numbered=True)
        _md_list(lines, "Validation steps", h.validation_steps)
        _md_list(lines, "Contest-validity notes", h.contest_validity_notes)
        _md_list(lines, "Evidence", h.evidence)
    return "\n".join(lines).rstrip() + "\n"


def _extract_functions(analysis: Mapping[str, Any]) -> list[FunctionSignal]:
    out: list[FunctionSignal] = []

    for item in analysis.get("transitions", []) or []:
        if not isinstance(item, Mapping):
            continue
        out.append(
            FunctionSignal(
                contract=str(item.get("contract") or "UnknownContract"),
                name=str(item.get("function") or item.get("name") or "unknown"),
                visibility=item.get("visibility"),
                modifiers=_as_str_list(item.get("modifiers")),
                reads=_as_str_list(item.get("reads_storage") or item.get("reads")),
                writes=_as_str_list(item.get("writes_storage") or item.get("writes")),
                external_calls=_as_str_list(item.get("external_calls")),
                asset_movements=_as_str_list(item.get("asset_movements")),
                authorization_hints=_as_str_list(item.get("auth_requirements") or item.get("authorization_hints")),
                body=str(item.get("body") or ""),
                raw=dict(item),
            )
        )

    # Add function bodies from model when no matching transition exists or to enrich body/visibility data.
    by_name = {fn.fq_name: fn for fn in out}
    model = analysis.get("model") or {}
    contracts = model.get("contracts") if isinstance(model, Mapping) else []
    for contract in contracts or []:
        if not isinstance(contract, Mapping):
            continue
        cname = str(contract.get("name") or "UnknownContract")
        for fn in contract.get("functions", []) or []:
            if not isinstance(fn, Mapping):
                continue
            name = str(fn.get("name") or "unknown")
            fq = f"{cname}.{name}"
            existing = by_name.get(fq)
            if existing:
                if not existing.body:
                    existing.body = str(fn.get("body") or "")
                if existing.visibility is None:
                    existing.visibility = fn.get("visibility")
                if not existing.modifiers:
                    existing.modifiers = _as_str_list(fn.get("modifiers"))
                continue
            out.append(
                FunctionSignal(
                    contract=cname,
                    name=name,
                    visibility=fn.get("visibility"),
                    modifiers=_as_str_list(fn.get("modifiers")),
                    body=str(fn.get("body") or ""),
                    raw=dict(fn),
                )
            )
    return out


def _precision_filter(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    """Drop or downgrade noisy heuristic matches.

    This pass intentionally prefers fewer, sharper hypotheses over broad scanner-like warnings.
    """
    filtered: list[Hypothesis] = []

    for h in hypotheses:
        hid = h.id.lower()
        fn_text = " ".join(h.related_functions).lower()
        evidence_text = " ".join(h.evidence).lower()
        state_text = " ".join(h.related_state).lower()

        is_config_setter = any(
            token in fn_text
            for token in ("set", "configure", "update", "setrewardrate", "setfee", "setoracle", "setadmin")
        )
        config_state = any(
            token in state_text or token in evidence_text or token in fn_text
            for token in ("rewardrate", "fee", "admin", "owner", "keeper", "oracle", "config", "parameter")
        )
        has_admin_evidence = any(
            token in evidence_text
            for token in ("onlyowner", "onlyrole", "admin", "governance", "owner")
        )
        is_admin_config = is_config_setter and (config_state or has_admin_evidence)

        if hid.startswith("price-manipulation:"):
            has_price_evidence = any(
                k in evidence_text or k in state_text or k in fn_text
                for k in ("oracle", "price", "twap", "chainlink", "pyth", "pool", "reserve", "sqrtprice")
            )
            if not has_price_evidence:
                continue

        if is_admin_config and (
            hid.startswith("accounting-no-assets:")
            or hid.startswith("reward-snapshot:")
            or hid.startswith("price-manipulation:")
        ):
            continue

        if hid.startswith("asset-move-no-auth:"):
            entitlement_shaped = any(k in fn_text for k in ("withdraw", "claim", "redeem", "unstake", "burn"))
            has_user_accounting = any(k in state_text or k in evidence_text for k in ("shares", "balance", "lastclaim", "debt", "position"))
            if entitlement_shaped and has_user_accounting:
                continue

        if hid.startswith("external-call-order:") and "deposit" in fn_text and "transferfrom" in evidence_text:
            h = h.model_copy(update={"severity_guess": "medium", "confidence": min(h.confidence, 0.48)})

        filtered.append(h)

    return filtered

def _rank_hypotheses(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    priority = {
        "external-call-order": 0,
        "share-manipulation": 1,
        "reward-snapshot": 2,
        "debt-liquidation-drift": 3,
        "accounting-no-assets": 4,
        "asset-move-no-auth": 5,
        "price-manipulation": 6,
        "privilege-review": 7,
    }

    def key(h: Hypothesis) -> tuple[int, float, str]:
        prefix = h.id.split(":", 1)[0]
        return (priority.get(prefix, 99), -h.confidence, h.id)

    return sorted(hypotheses, key=key)


def _dedupe_hypotheses(hypotheses: list[Hypothesis]) -> list[Hypothesis]:
    seen: set[str] = set()
    out: list[Hypothesis] = []
    for h in hypotheses:
        if h.id in seen:
            continue
        seen.add(h.id)
        out.append(h)
    return out


def _looks_like_admin_config_setter(blob: str) -> bool:
    return any(k in blob for k in ("setrewardrate", "setfee", "setoracle", "setadmin", "setowner")) or "onlyowner" in blob


def _looks_like_entitlement_path(blob: str) -> bool:
    has_entitlement_name = any(k in blob for k in ("withdraw", "claim", "redeem"))
    has_user_accounting = any(k in blob for k in ("shares", "balance", "lastclaim", "amountout", "msg.sender", "sender"))
    return has_entitlement_name and has_user_accounting


def _hid(prefix: str, fq_name: str) -> str:
    return f"{prefix}:{fq_name.replace('.', '-').lower()}"


def _joined(values: list[Any]) -> str:
    return " ".join(str(v).lower() for v in values if v is not None)


def _as_str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list | tuple | set):
        return [str(v) for v in value if v is not None]
    return [str(value)]


def _md_list(lines: list[str], title: str, items: list[str], numbered: bool = False) -> None:
    if not items:
        return
    lines.extend([f"### {title}"])
    for i, item in enumerate(items, start=1):
        marker = f"{i}." if numbered else "-"
        lines.append(f"{marker} {item}")
    lines.append("")


_ACCOUNTING_TERMS = (
    "asset",
    "assets",
    "share",
    "shares",
    "totalsupply",
    "totalshares",
    "balance",
    "debt",
    "collateral",
    "reward",
    "liability",
    "reserve",
)

_SHARE_TERMS = (
    "share",
    "shares",
    "totalshares",
    "totalsupply",
    "totalassets",
    "converttoassets",
    "converttoshares",
    "balanceof",
)

_REWARD_TERMS = (
    "reward",
    "rewards",
    "claim",
    "lastclaim",
    "checkpoint",
    "emission",
    "accrue",
)

_PRICE_TERMS = (
    "oracle",
    "price",
    "twap",
    "chainlink",
    "pyth",
    "pool",
    "reserve0",
    "reserve1",
    "uniswap",
    "curve",
    "feed",
)

# --- v3.4 primer-backed archetype injection ---
_ORIGINAL_GENERATE_V34 = HypothesisEngine.generate


def _v34_contains(items: list[str], *needles: str) -> bool:
    haystack = " ".join(str(x).lower() for x in items)
    return any(n.lower() in haystack for n in needles)


def _v34_primer_backed_hypotheses(functions: list[FunctionSignal]) -> list[Hypothesis]:
    """Primer-backed vault/staking exploit archetypes.

    These are narrow on purpose: they should produce concrete audit prompts,
    not a wall of generic warnings.
    """
    out: list[Hypothesis] = []

    for fn in functions:
        fn_name = fn.name.lower()
        read_write = [*fn.reads, *fn.writes]
        call_text = " ".join(fn.external_calls).lower()

        is_deposit_like = any(k in fn_name for k in ("deposit", "mint", "stake", "addliquidity"))
        is_withdraw_like = any(k in fn_name for k in ("withdraw", "redeem", "unstake", "remove"))
        is_reward_claim = any(k in fn_name for k in ("claim", "getreward", "harvest", "collect"))

        share_state = _v34_contains(read_write, "share", "shares", "totalshares", "totalsupply")
        reward_state = _v34_contains(read_write, "reward", "rewards", "rewardrate", "lastclaim", "emission")
        amount_state = _v34_contains(read_write, "amount", "assets", "asset", "balance")

        if (
            fn.is_public_entrypoint
            and is_deposit_like
            and "transferfrom" in call_text
            and share_state
            and amount_state
        ):
            out.append(
                Hypothesis(
                    id=_hid("fot-accounting-mismatch", fn.fq_name),
                    title="Deposit accounting may assume transferred amount equals received amount",
                    severity_guess="high",
                    confidence=0.64,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=sorted(set(read_write)),
                    invariant="Share/accounting updates should be based on actual tokens received, not the user-supplied transfer amount.",
                    attack_preconditions=[
                        "The accepted asset can be fee-on-transfer, rebasing, hook-enabled, or otherwise non-standard.",
                        "The function uses the nominal input amount for shares/accounting instead of a balance delta.",
                    ],
                    exploit_sketch=[
                        f"Use a token or mocked asset where transferFrom receives less than the requested amount in {fn.fq_name}.",
                        "Observe shares/accounting minted from the nominal amount.",
                        "Withdraw later against inflated accounting, pushing losses to the protocol or later users.",
                    ],
                    validation_steps=[
                        "Add a mock fee-on-transfer token and rerun deposit/withdraw sequences.",
                        "Assert actual balance delta equals the amount used for share/accounting updates.",
                        "If the contest excludes weird tokens, confirm whether the asset is fixed/allowlisted before reporting.",
                    ],
                    contest_validity_notes=[
                        "Strong when protocol claims arbitrary ERC20 support or the in-scope asset can have transfer fees/hooks/rebasing.",
                        "Likely invalid if the protocol explicitly only supports known standard tokens and the contest excludes weird-token behavior.",
                    ],
                    evidence=[
                        f"reads={fn.reads}",
                        f"writes={fn.writes}",
                        f"external_calls={fn.external_calls}",
                    ],
                    tags=["fee-on-transfer", "token-compatibility", "accounting", "vault"],
                )
            )

        if fn.is_public_entrypoint and is_deposit_like and share_state and amount_state:
            has_min_hint = _v34_contains(
                read_write + [fn.name],
                "minshare",
                "minshares",
                "minout",
                "amountoutmin",
                "slippage",
            )
            if not has_min_hint:
                out.append(
                    Hypothesis(
                        id=_hid("missing-min-shares", fn.fq_name),
                        title="Vault deposit may lack minimum shares / slippage protection",
                        severity_guess="medium",
                        confidence=0.52,
                        affected_contracts=[fn.contract],
                        related_functions=[fn.fq_name],
                        related_state=sorted(set(read_write)),
                        invariant="Depositors should be able to bound the minimum shares received from a deposit/mint action.",
                        attack_preconditions=[
                            "Share price can move between user signing and execution, or can be manipulated by donation/sandwiching.",
                            "The deposit path does not let the user specify minimum acceptable shares.",
                        ],
                        exploit_sketch=[
                            "Manipulate the share price with a donation, sandwich, or state-changing action before the victim deposit.",
                            f"Let the victim call {fn.fq_name} without a min-shares guard.",
                            "Victim receives fewer shares than expected while existing holders or attacker capture value.",
                        ],
                        validation_steps=[
                            "Check the public function signature for minShares/minOut/deadline-style parameters.",
                            "Simulate donation or share-price movement immediately before deposit.",
                            "Compare victim shares against an off-chain quoted expectation.",
                        ],
                        contest_validity_notes=[
                            "Usually medium/high only when a realistic MEV or donation path creates material value loss.",
                            "May be low/invalid if UI-only slippage is expected and no realistic manipulation path exists.",
                        ],
                        evidence=[
                            f"function={fn.fq_name}",
                            f"reads={fn.reads}",
                            f"writes={fn.writes}",
                        ],
                        tags=["slippage", "shares", "vault", "mev"],
                    )
                )

        if (
            fn.is_public_entrypoint
            and is_reward_claim
            and reward_state
            and share_state
            and ("transfer" in call_text or fn.has_asset_movement)
        ):
            out.append(
                Hypothesis(
                    id=_hid("reward-insolvency", fn.fq_name),
                    title="Reward claims may drain the same asset reserve backing withdrawals",
                    severity_guess="high",
                    confidence=0.60,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=sorted(set(read_write)),
                    invariant="Reward liabilities should be funded separately or capped so principal/share redemptions remain solvent.",
                    attack_preconditions=[
                        "Rewards are paid from the same ERC20 balance used to satisfy withdrawals or redemptions.",
                        "Reward accrual can exceed separately funded rewards or has no explicit reserve/cap.",
                    ],
                    exploit_sketch=[
                        "Build up reward entitlement through time warp, balance manipulation, or high reward rate.",
                        f"Call {fn.fq_name} until the vault's asset balance is reduced.",
                        "Attempt honest withdrawals and check whether share liabilities exceed remaining assets.",
                    ],
                    validation_steps=[
                        "Track reward liabilities separately from principal liabilities in a Foundry invariant.",
                        "Warp time and claim as multiple users, then assert all shares remain redeemable.",
                        "Check whether admin-set reward rates can exceed funded reward reserves.",
                    ],
                    contest_validity_notes=[
                        "Strong if permissionless users can drain principal or make later withdrawals insolvent.",
                        "Admin-set emission rates may be invalid alone, but missing solvency caps can still matter if docs promise safety.",
                    ],
                    evidence=[
                        f"reads={fn.reads}",
                        f"writes={fn.writes}",
                        f"external_calls={fn.external_calls}",
                    ],
                    tags=["rewards", "insolvency", "accounting", "vault"],
                )
            )

        if fn.is_public_entrypoint and is_withdraw_like and share_state and amount_state:
            out.append(
                Hypothesis(
                    id=_hid("withdraw-rounding-dust", fn.fq_name),
                    title="Withdrawal/share conversion should be checked for dust or zero-rounding edge cases",
                    severity_guess="medium",
                    confidence=0.43,
                    affected_contracts=[fn.contract],
                    related_functions=[fn.fq_name],
                    related_state=sorted(set(read_write)),
                    invariant="Withdraw/redeem conversions should not allow asset movement with zero/too-few shares burned or permanently strand user dust.",
                    attack_preconditions=[
                        "Conversion math rounds in the wrong direction or permits zero-share/zero-asset edge cases.",
                        "Repeated small operations can accumulate value leakage or lock funds.",
                    ],
                    exploit_sketch=[
                        "Test tiny share amounts, tiny asset amounts, high exchange-rate states, and donated-balance states.",
                        f"Call {fn.fq_name} repeatedly around rounding boundaries.",
                        "Check for free withdrawal, stuck dust, or systematic value leakage.",
                    ],
                    validation_steps=[
                        "Create boundary tests for 0, 1 wei, max, and high exchange-rate cases.",
                        "Assert withdrawing assets always burns at least the correct shares.",
                        "Assert redeeming shares always returns a fair nonzero/expected asset amount when economically meaningful.",
                    ],
                    contest_validity_notes=[
                        "Escalate only with a repeatable profit/loss path. Pure dust or self-harm is often invalid.",
                    ],
                    evidence=[
                        f"reads={fn.reads}",
                        f"writes={fn.writes}",
                        f"external_calls={fn.external_calls}",
                    ],
                    tags=["rounding", "dust", "shares", "vault"],
                )
            )

    return out


def _generate_v34(self: HypothesisEngine, analysis: Mapping[str, Any]) -> list[Hypothesis]:
    functions = _extract_functions(analysis)
    hypotheses = list(_ORIGINAL_GENERATE_V34(self, analysis))
    hypotheses.extend(_v34_primer_backed_hypotheses(functions))
    return _dedupe_hypotheses(_precision_filter(hypotheses))


HypothesisEngine.generate = _generate_v34

# --- v3.5 access-control takeover archetype ---
# --- v3.5 access-control takeover archetype ---

_ORIGINAL_GENERATE_V35 = HypothesisEngine.generate


def _v35_access_control_hypotheses(functions: list[FunctionSignal]) -> list[Hypothesis]:
    out: list[Hypothesis] = []

    sensitive_state_terms = (
        "owner",
        "pendingowner",
        "admin",
        "governance",
        "governor",
        "guardian",
        "operator",
        "keeper",
        "role",
        "authority",
        "implementation",
        "proxy",
        "upgrade",
        "pauser",
        "treasury",
        "oracle",
    )

    sensitive_function_terms = (
        "setowner",
        "transferownership",
        "acceptownership",
        "setadmin",
        "grantrole",
        "revokerole",
        "setgovernance",
        "setgovernor",
        "setoperator",
        "setkeeper",
        "setguardian",
        "upgrade",
        "setimplementation",
        "setoracle",
        "settreasury",
        "setfee",
        "setrewardrate",
        "pause",
        "unpause",
    )

    for fn in functions:
        fn_name = fn.name.lower()
        state_text = " ".join([*fn.reads, *fn.writes]).lower()
        auth_requirements = [str(x) for x in fn.raw.get("auth_requirements", [])]
        evidence_text = " ".join([*auth_requirements, *fn.modifiers]).lower()

        writes_sensitive_state = any(term in state_text for term in sensitive_state_terms)
        sensitive_name = any(term in fn_name for term in sensitive_function_terms)
        has_auth = bool(auth_requirements or fn.modifiers) or any(
            term in evidence_text
            for term in ("onlyowner", "onlyrole", "requiresrole", "admin", "governance", "owner")
        )

        if not fn.is_public_entrypoint:
            continue

        if has_auth:
            continue

        entitlement_name = any(
            term in fn_name
            for term in ("claim", "withdraw", "redeem", "deposit", "mint", "burn", "stake", "unstake")
        )

        if entitlement_name and not sensitive_name and not writes_sensitive_state:
            continue

        if not (writes_sensitive_state or sensitive_name):
            continue

        out.append(
            Hypothesis(
                id=_hid("missing-access-control", fn.fq_name),
                title="Sensitive control-plane function appears externally callable without authorization",
                severity_guess="high",
                confidence=0.72,
                affected_contracts=[fn.contract],
                related_functions=[fn.fq_name],
                related_state=sorted(set([*fn.reads, *fn.writes])),
                invariant="Only authorized roles should be able to change ownership, roles, governance, upgrade, oracle, fee, pause, or other privileged configuration state.",
                attack_preconditions=[
                    "The function is externally/publicly reachable.",
                    "The function writes privileged state or has a sensitive setter/role-management name.",
                    "There is no modifier or explicit authorization requirement detected.",
                ],
                exploit_sketch=[
                    f"Call {fn.fq_name} from an arbitrary non-admin address.",
                    "Set owner/admin/role/configuration to attacker-controlled values or unsafe parameters.",
                    "Use the gained control path to drain funds, block users, alter pricing, upgrade logic, or bypass intended governance.",
                ],
                validation_steps=[
                    "Confirm the Solidity body lacks msg.sender/role validation, modifiers, or internal-only routing.",
                    "Write a Foundry test where a random address calls the function successfully.",
                    "Check what privileged follow-up actions become possible after the unauthorized state change.",
                ],
                contest_validity_notes=[
                    "Strong when a non-admin can take ownership, grant roles, upgrade, pause, change oracle/fees, or alter critical parameters.",
                    "Do not report if the function is intentionally permissionless and cannot affect user funds, pricing, liveness, or privileged control.",
                ],
                evidence=[
                    f"reads={fn.reads}",
                    f"writes={fn.writes}",
                    f"modifiers={fn.modifiers}",
                    f"auth_requirements={auth_requirements}",
                ],
                tags=["access-control", "privilege", "ownership", "control-plane"],
            )
        )

    return out


def _generate_v35(self: HypothesisEngine, analysis: Mapping[str, Any]) -> list[Hypothesis]:
    functions = _extract_functions(analysis)
    hypotheses = list(_ORIGINAL_GENERATE_V35(self, analysis))
    hypotheses.extend(_v35_access_control_hypotheses(functions))
    return _dedupe_hypotheses(_precision_filter(hypotheses))


HypothesisEngine.generate = _generate_v35

# --- v3.6 oracle / spot-price manipulation archetype ---
# --- v3.6 oracle / spot-price manipulation archetype ---

_ORIGINAL_GENERATE_V36 = HypothesisEngine.generate


def _v36_oracle_price_hypotheses(functions: list[FunctionSignal]) -> list[Hypothesis]:
    out: list[Hypothesis] = []

    price_terms = (
        "price",
        "oracle",
        "quote",
        "getethprice",
        "getprice",
        "spot",
        "reserve",
        "pool",
        "weth",
        "usdc",
        "usd",
    )

    reserve_terms = (
        "balanceof",
        "reserve",
        "pool",
        "swap",
        "getoutputamount",
        "getinputamount",
        "liquidity",
        "amm",
        "exchange",
    )

    for fn in functions:
        fn_name = fn.name.lower()
        contract_name = fn.contract.lower()
        state_text = " ".join([*fn.reads, *fn.writes]).lower()
        call_text = " ".join(fn.external_calls).lower()
        raw_text = str(fn.raw).lower()
        combined = " ".join([fn_name, contract_name, state_text, call_text, raw_text])

        price_named = any(term in combined for term in price_terms)
        reserve_based = any(term in combined for term in reserve_terms)

        # A view/pure price function using balances/reserves/pool math is a likely spot-price oracle source.
        is_price_source = price_named and reserve_based

        # A payable buy/mint path that calls/depends on a price function is a likely victim path.
        is_price_consumer = (
            any(term in fn_name for term in ("buy", "mint", "purchase", "swap"))
            and any(term in combined for term in ("price", "oracle", "quote", "exchange"))
        )

        if not (is_price_source or is_price_consumer):
            continue

        out.append(
            Hypothesis(
                id=_hid("oracle-spot-price-manipulation", fn.fq_name),
                title="Protocol pricing may rely on manipulable spot reserves or exchange balance state",
                severity_guess="high",
                confidence=0.67 if is_price_source else 0.58,
                affected_contracts=[fn.contract],
                related_functions=[fn.fq_name],
                related_state=sorted(set([*fn.reads, *fn.writes])),
                invariant="Protocol pricing should not depend on instantly manipulable AMM spot reserves or raw token balances without TWAP, oracle hardening, or manipulation bounds.",
                attack_preconditions=[
                    "The pricing path reads exchange reserves, pool balances, or spot swap output.",
                    "An attacker can trade, flash-loan, donate, or otherwise move those reserves before the priced action.",
                    "The priced action mints, buys, redeems, liquidates, or transfers value using the manipulated quote.",
                ],
                exploit_sketch=[
                    "Move the pool/exchange price with a large swap, flash loan, or temporary reserve imbalance.",
                    f"Call {fn.fq_name} or a dependent buy/mint/redeem path while the spot quote is distorted.",
                    "Reverse the manipulation if possible and keep the underpriced asset, excess output, or unfair liquidation result.",
                ],
                validation_steps=[
                    "Identify whether the quote uses raw balanceOf/reserves or same-block AMM spot output.",
                    "Simulate a large swap or flash-loan-like reserve change before the priced action.",
                    "Compare protocol output against a non-manipulated reference price or time-weighted price.",
                ],
                contest_validity_notes=[
                    "Strong when the manipulated quote lets an attacker buy/mint/redeem/liquidate for profit or causes protocol insolvency.",
                    "Avoid reporting if the price source is intentionally trusted, bounded, delayed, or protected by TWAP/oracle checks.",
                ],
                evidence=[
                    f"function={fn.fq_name}",
                    f"reads={fn.reads}",
                    f"writes={fn.writes}",
                    f"external_calls={fn.external_calls}",
                ],
                tags=["oracle", "price-manipulation", "oracle-spot-price", "amm", "spot-price"],
            )
        )

    return out


def _generate_v36(self: HypothesisEngine, analysis: Mapping[str, Any]) -> list[Hypothesis]:
    functions = _extract_functions(analysis)
    hypotheses = list(_ORIGINAL_GENERATE_V36(self, analysis))
    hypotheses.extend(_v36_oracle_price_hypotheses(functions))
    return _dedupe_hypotheses(_precision_filter(hypotheses))


HypothesisEngine.generate = _generate_v36
