from pathlib import Path

from audit_copilot.solidity_parser import collect_contracts
from audit_copilot.transitions import extract_transitions


ROOT = Path(__file__).parents[1]
SAMPLE_ROOT = ROOT / "examples" / "sample_protocol"
CEI_SAFE_ROOT = ROOT / "examples" / "exploit_fixtures" / "negative" / "cei_safe_withdraw"


def _transition_by_function(transitions, contract: str, function: str):
    return next(
        transition
        for transition in transitions
        if transition.contract == contract and transition.function == function
    )


def test_extract_transitions_identifies_sample_vault_asset_flows():
    contracts = collect_contracts(SAMPLE_ROOT)
    transitions = extract_transitions(contracts)

    deposit = _transition_by_function(transitions, "SimpleVault", "deposit")
    withdraw = _transition_by_function(transitions, "SimpleVault", "withdraw")
    claim_rewards = _transition_by_function(transitions, "SimpleVault", "claimRewards")

    assert deposit.writes_storage == ["shares", "totalShares"]
    assert deposit.external_calls == ["transferFrom"]
    assert deposit.asset_movements == ["token movement/mint/burn"]
    assert "Deposit" in deposit.emits

    assert withdraw.writes_storage == ["shares", "totalShares"]
    assert withdraw.external_calls == ["transfer"]
    assert withdraw.asset_movements == ["token movement/mint/burn"]
    assert "Withdraw" in withdraw.emits

    assert claim_rewards.writes_storage == ["lastClaim"]
    assert claim_rewards.external_calls == ["transfer"]
    assert claim_rewards.asset_movements == ["token movement/mint/burn"]
    assert "Claim" in claim_rewards.emits


def test_extract_transitions_captures_auth_requirements():
    contracts = collect_contracts(SAMPLE_ROOT)
    transitions = extract_transitions(contracts)

    set_reward_rate = _transition_by_function(transitions, "SimpleVault", "setRewardRate")

    assert set_reward_rate.writes_storage == ["rewardRate"]
    assert set_reward_rate.auth_requirements == ["onlyOwner"]
    assert set_reward_rate.external_calls == []
    assert set_reward_rate.asset_movements == []


def test_extract_transitions_marks_cei_safe_withdraw_ordering():
    contracts = collect_contracts(CEI_SAFE_ROOT)
    transitions = extract_transitions(contracts)

    withdraw = _transition_by_function(transitions, "CeiSafeWithdraw", "withdraw")

    assert withdraw.writes_storage == ["balances"]
    assert withdraw.external_calls == ["low-level external call"]
    assert "state write appears before external interaction" in withdraw.notes
    assert "cei effects-before-interaction ordering" in withdraw.notes
    assert "external interaction appears before state write" not in withdraw.notes
    assert "cei interaction-before-effects ordering" not in withdraw.notes
