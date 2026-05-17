from __future__ import annotations

from .models import InvariantCandidate, ProtocolModel, StateTransition


def generate_invariants(model: ProtocolModel, transitions: list[StateTransition]) -> list[InvariantCandidate]:
    invariants: list[InvariantCandidate] = []
    idx = 1

    accounting_names = {x.lower() for x in model.accounting_systems}
    if any("balance" in x or "share" in x or "supply" in x or "asset" in x for x in accounting_names):
        invariants.append(InvariantCandidate(
            id=f"INV-{idx:03d}",
            title="Accounting conservation must hold across deposits, withdrawals, minting, and burning",
            description="Users should not be able to withdraw, claim, mint, or redeem more value than their deposited/priced/earned entitlement.",
            related_contracts=[c.name for c in model.contracts],
            category="accounting",
            attack_questions=[
                "Can shares/assets become desynchronized by ordering deposits, donations, withdrawals, or claims?",
                "Can rounding favor an attacker across repeated small transactions?",
                "Can total supply or total assets be changed without updating user accounting?",
            ],
            foundry_hint="Create invariant asserting protocol balance and sum of user claims remain consistent after arbitrary action sequences.",
        ))
        idx += 1

    asset_transitions = [t for t in transitions if t.asset_movements]
    if asset_transitions:
        invariants.append(InvariantCandidate(
            id=f"INV-{idx:03d}",
            title="Permissionless asset-moving functions must preserve user entitlement",
            description="Any public/external function moving ETH/tokens must enforce the caller's entitlement and update storage before unsafe external interactions.",
            related_contracts=sorted({t.contract for t in asset_transitions}),
            related_functions=[f"{t.contract}.{t.function}" for t in asset_transitions],
            category="asset-flow",
            attack_questions=[
                "Can a caller move assets belonging to another user?",
                "Can reentrancy observe stale balances or claim checkpoints?",
                "Can failed token transfers leave accounting in an impossible state?",
            ],
            foundry_hint="Write handler sequences around deposit/withdraw/claim and assert attacker cannot increase net worth unfairly.",
        ))
        idx += 1

    timed = [t for t in transitions if t.timing_dependencies]
    if timed:
        invariants.append(InvariantCandidate(
            id=f"INV-{idx:03d}",
            title="Time-dependent logic must not allow stale checkpoint or boundary abuse",
            description="Epochs, deadlines, rounds, and cooldowns should not create exploitable state gaps at boundaries.",
            related_contracts=sorted({t.contract for t in timed}),
            related_functions=[f"{t.contract}.{t.function}" for t in timed],
            category="temporal",
            attack_questions=[
                "Can an attacker act before and after a checkpoint to double count rewards?",
                "Can a stale round/epoch be used to settle using outdated assumptions?",
                "Can block timestamp tolerance materially alter reward or settlement math?",
            ],
            foundry_hint="Use vm.warp/vm.roll around epoch boundaries and compare expected vs achievable state.",
        ))
        idx += 1

    privileged = [t for t in transitions if t.auth_requirements]
    if privileged:
        invariants.append(InvariantCandidate(
            id=f"INV-{idx:03d}",
            title="Privileged controls must not be reachable by unprivileged actors",
            description="Role-gated state transitions should remain inaccessible to arbitrary users; contest validity depends on whether admin behavior is assumed correct.",
            related_contracts=sorted({t.contract for t in privileged}),
            related_functions=[f"{t.contract}.{t.function}" for t in privileged],
            category="access-control",
            attack_questions=[
                "Can initialization, role assignment, or ownership transfer be front-run or repeated?",
                "Can modifiers be bypassed through inherited/public helper functions?",
                "Is the issue actually admin-only and therefore invalid for this contest?",
            ],
            foundry_hint="Prank as unprivileged users and assert protected transitions revert.",
        ))
        idx += 1

    integrations = model.integrations
    if integrations:
        invariants.append(InvariantCandidate(
            id=f"INV-{idx:03d}",
            title="External integrations must not become single-point accounting or pricing failure modes",
            description="Routers, pools, bridges, and oracles should not be trusted beyond stated assumptions and contest scope.",
            related_contracts=[c.name for c in model.contracts],
            category="integration",
            attack_questions=[
                "Can stale prices, manipulated reserves, or delayed oracle updates shift value?",
                "Can an integration callback reenter or reorder settlement?",
                "Is the integration behavior in scope or explicitly out of scope?",
            ],
            foundry_hint="Mock integrations and simulate stale/manipulated values while checking protocol accounting invariants.",
        ))
        idx += 1

    if not invariants:
        invariants.append(InvariantCandidate(
            id="INV-001",
            title="Core state machine should be impossible to move into contradictory state",
            description="Identify intended states and assert impossible transitions cannot be reached by arbitrary call sequences.",
            related_contracts=[c.name for c in model.contracts],
            category="state-machine",
            attack_questions=[
                "Which states should be mutually exclusive?",
                "Can a user skip required phases?",
                "Can settlement happen twice or before commitment/finalization?",
            ],
            foundry_hint="Build a handler that calls public functions in arbitrary order and assert phase/state constraints.",
        ))
    return invariants
