from __future__ import annotations

import re
from .models import ContractInfo, StateTransition

CALL_RE = re.compile(r"\.\s*(call|delegatecall|staticcall|transfer|send)\s*(?:\{|\()")
TOKEN_CALL_RE = re.compile(r"\.(transfer|transferFrom|safeTransfer|safeTransferFrom|mint|burn)\s*\(")
EVENT_RE = re.compile(r"emit\s+([A-Za-z_][A-Za-z0-9_]*)")
ASSIGN_RE = re.compile(r"([A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]+\])?)\s*(?:\+\+|--|[+\-*/]?=)")

AUTH_HINTS = ["onlyOwner", "onlyAdmin", "onlyRole", "hasRole", "msg.sender == owner", "msg.sender==owner", "require(msg.sender"]
TIME_HINTS = ["block.timestamp", "block.number", "deadline", "epoch", "round", "cooldown", "vesting"]


def extract_transitions(contracts: list[ContractInfo]) -> list[StateTransition]:
    transitions: list[StateTransition] = []
    state_vars_by_contract = {c.name: set(c.state_variables) for c in contracts}

    for c in contracts:
        state_vars = state_vars_by_contract[c.name]
        for fn in c.functions:
            if fn.view_or_pure:
                continue
            body = fn.body
            writes = sorted({m.group(1).split("[")[0] for m in ASSIGN_RE.finditer(body) if m.group(1).split("[")[0] in state_vars})
            reads = sorted({v for v in state_vars if re.search(rf"\b{re.escape(v)}\b", body) and v not in writes})
            ext = []
            if CALL_RE.search(body):
                ext.append("low-level external call")
            ext.extend(sorted(set(TOKEN_CALL_RE.findall(body))))
            auth = []
            if fn.modifiers:
                auth.extend(fn.modifiers)
            auth.extend([h for h in AUTH_HINTS if h in body])
            assets = []
            if "msg.value" in body or fn.payable:
                assets.append("native ETH movement")
            if TOKEN_CALL_RE.search(body):
                assets.append("token movement/mint/burn")
            timing = [h for h in TIME_HINTS if h in body.lower() or h in body]
            notes = []
            notes.extend(_body_notes(body))
            if ext and writes:
                notes.append("external interaction and storage write appear in same transition; check CEI and reentrancy assumptions")
            if assets and not auth and fn.visibility in {"public", "external"}:
                notes.append("permissionless asset movement; validate accounting and caller constraints")
            transitions.append(StateTransition(
                contract=c.name,
                function=fn.name,
                reads_storage=reads,
                writes_storage=writes,
                external_calls=ext,
                auth_requirements=sorted(set(auth)),
                asset_movements=sorted(set(assets)),
                emits=sorted(set(EVENT_RE.findall(body))),
                timing_dependencies=sorted(set(timing)),
                notes=notes,
            ))
    return transitions


def _body_notes(source: str) -> list[str]:
    lowered = source.lower()
    notes: list[str] = []

    if "converttoshares" in lowered:
        notes.append("calls convertToShares")

    if "previewdeposit" in lowered:
        notes.append("uses previewDeposit")

    if "shares > 0" in lowered or "shares>0" in lowered or "zero_shares" in lowered:
        notes.append("has nonzero shares guard")

    if "minshares" in lowered or "min_shares" in lowered or "minout" in lowered or "amountoutmin" in lowered:
        notes.append("has min shares/slippage parameter")

    if "totalassets()" in lowered or "balanceof(address(this))" in lowered:
        notes.append("uses live asset balance")

    return notes


def _function_window_notes(contract_source: str, function_name: str) -> list[str]:
    lowered_source = contract_source.lower()
    lowered_name = function_name.lower()
    notes: list[str] = []

    # Find a local window around the function declaration/name. This is intentionally
    # heuristic but much better than relying on parser hints that may omit body details.
    idx = lowered_source.find("function " + lowered_name)
    if idx == -1:
        idx = lowered_source.find(lowered_name)

    if idx == -1:
        window = lowered_source
    else:
        window = lowered_source[idx: idx + 2500]

    if "converttoshares" in window:
        notes.append("calls convertToShares")

    if "previewdeposit" in window:
        notes.append("uses previewDeposit")

    if "shares > 0" in window or "shares>0" in window or "zero_shares" in window:
        notes.append("has nonzero shares guard")

    if "minshares" in window or "min_shares" in window or "minout" in window or "amountoutmin" in window:
        notes.append("has min shares/slippage parameter")

    if "totalassets()" in window or "balanceof(address(this))" in window:
        notes.append("uses live asset balance")

    return notes
