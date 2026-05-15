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
