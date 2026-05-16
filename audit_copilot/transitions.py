from __future__ import annotations

import re
from .models import ContractInfo, StateTransition

CALL_RE = re.compile(r"\.\s*(call|delegatecall|staticcall|transfer|send)\s*(?:\{|\()")
TOKEN_CALL_RE = re.compile(r"\.(transfer|transferFrom|safeTransfer|safeTransferFrom|mint|burn)\s*\(")
ORACLE_CALL_RE = re.compile(r"\.(latestRoundData|getRoundData|getReserves|slot0|consult)\s*\(")
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
            body = fn.body
            lowered_body = body.lower()

            # Most view/pure functions are not state transitions, but oracle-dependent
            # read functions can still be security-critical when used for quotes,
            # mint/redeem math, settlement, liquidation, or accounting.
            keep_security_relevant_view = (
                fn.view_or_pure
                and (
                    "latestrounddata" in lowered_body
                    or "getreserves" in lowered_body
                    or "slot0" in lowered_body
                    or "consult" in lowered_body
                    or "twap" in lowered_body
                    or "oracle" in lowered_body
                )
            )

            if fn.view_or_pure and not keep_security_relevant_view:
                continue
            writes = sorted({m.group(1).split("[")[0] for m in ASSIGN_RE.finditer(body) if m.group(1).split("[")[0] in state_vars})
            reads = sorted({v for v in state_vars if re.search(rf"\b{re.escape(v)}\b", body) and v not in writes})
            ext = []
            if CALL_RE.search(body):
                ext.append("low-level external call")
            ext.extend(sorted(set(TOKEN_CALL_RE.findall(body))))
            ext.extend(sorted(set(ORACLE_CALL_RE.findall(body))))
            ext.extend(sorted(set(ORACLE_CALL_RE.findall(body))))
            ext.extend(sorted(set(ORACLE_CALL_RE.findall(body))))
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
            notes.extend(_oracle_value_flow_notes(body, state_vars))
            notes.extend(_cei_order_notes(body, state_vars))
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

    if "address(this).balance" in lowered:
        notes.append("uses native address(this).balance")

    if "ecrecover" in lowered:
        notes.append("uses ecrecover")

    if ("for (" in lowered or "for(" in lowered) and ".length" in lowered:
        notes.append("has loop over dynamic length")

    if "selfdestruct" in lowered:
        notes.append("uses selfdestruct")

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


def _cei_order_notes(body: str, state_vars: set[str]) -> list[str]:
    notes: list[str] = []

    def is_local_declaration(match: re.Match[str]) -> bool:
        line_start = body.rfind("\n", 0, match.start()) + 1
        prefix = body[line_start:match.start()].strip()

        # Examples to ignore:
        # uint256 balance =
        # address receiver =
        # bool success =
        # (bool success,) =
        # Anything with an explicit type/declaration immediately before the target
        # is not a storage effect.
        declaration_markers = (
            "uint",
            "int",
            "address",
            "bool",
            "bytes",
            "string",
            "mapping",
            "contract",
            "IERC",
            "ERC",
            "(",
        )

        return prefix.startswith(declaration_markers)

    write_positions: list[int] = []
    for match in ASSIGN_RE.finditer(body):
        raw_target = match.group(1)
        var_name = raw_target.split("[")[0]

        if var_name not in state_vars:
            continue

        if is_local_declaration(match):
            continue

        write_positions.append(match.start())

    external_positions = [m.start() for m in CALL_RE.finditer(body)]
    external_positions.extend(m.start() for m in TOKEN_CALL_RE.finditer(body))

    if not write_positions or not external_positions:
        return notes

    first_write = min(write_positions)
    first_external = min(external_positions)

    if first_write < first_external:
        notes.append("state write appears before external interaction")
        notes.append("cei effects-before-interaction ordering")
    else:
        notes.append("external interaction appears before state write")
        notes.append("cei interaction-before-effects ordering")

    return notes


def _oracle_value_flow_notes(body: str, state_vars: set[str]) -> list[str]:
    lowered = body.lower()
    notes: list[str] = []

    uses_oracle_call = (
        "latestrounddata" in lowered
        or "getrounddata" in lowered
        or "getreserves" in lowered
        or "slot0" in lowered
        or "consult" in lowered
    )

    if not uses_oracle_call and "answer" not in lowered and "price" not in lowered:
        return notes

    if uses_oracle_call:
        notes.append("uses oracle call")

    if "latestrounddata" in lowered or "getrounddata" in lowered:
        notes.append("uses chainlink-style round data")

    if "answer" in lowered:
        notes.append("reads oracle answer")

    oracle_answer_math = (
        "answer)" in lowered
        or "uint256(answer)" in lowered
        or "* uint256(answer)" in lowered
        or "uint256(answer) /" in lowered
        or "* answer" in lowered
        or "answer /" in lowered
    )

    if oracle_answer_math:
        notes.append("uses oracle answer in arithmetic")

    if "updatedat" in lowered:
        notes.append("reads oracle updatedAt")

    if "answeredinround" in lowered:
        notes.append("reads oracle answeredInRound")

    freshness_patterns = (
        "block.timestamp - updatedat",
        "updatedat +",
        "updatedat >=",
        "updatedat!=",
        "updatedat !=",
        "max_staleness",
        "maxstaleness",
        "heartbeat",
        "stale_price",
        "staleprice",
        "stale_oracle",
        "staleoracle",
        "answeredinround >= roundid",
    )

    if any(pattern in lowered.replace(" ", "") for pattern in freshness_patterns):
        notes.append("has oracle freshness check")
    elif uses_oracle_call and ("updatedat" in lowered or "answer" in lowered):
        notes.append("missing oracle freshness check")

    writes_oracle_value = any(
        state_var.lower() in lowered and ("answer" in lowered or "usdvalue" in lowered or "price" in lowered)
        for state_var in state_vars
    )

    if writes_oracle_value:
        notes.append("writes oracle-derived value to state")

    if ".push(" in lowered and ("answer" in lowered or "usdvalue" in lowered or "price" in lowered):
        notes.append("pushes oracle-derived value to array")

    if "emit " in lowered and ("answer" in lowered or "usdvalue" in lowered or "price" in lowered):
        notes.append("emits oracle-derived value")

    return notes
