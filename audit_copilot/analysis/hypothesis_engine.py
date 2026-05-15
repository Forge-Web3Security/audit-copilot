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
