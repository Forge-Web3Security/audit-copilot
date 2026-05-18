from pathlib import Path

from audit_copilot.solidity_parser import collect_contracts, parse_solidity_file


ROOT = Path(__file__).parents[1]
SAMPLE_ROOT = ROOT / "examples" / "sample_protocol"
SIMPLE_VAULT = SAMPLE_ROOT / "src" / "SimpleVault.sol"


def _contract_by_name(contracts, name: str):
    return next(contract for contract in contracts if contract.name == name)


def _function_by_name(contract, name: str):
    return next(function for function in contract.functions if function.name == name)


def test_collect_contracts_recursively_parses_sample_protocol():
    contracts = collect_contracts(SAMPLE_ROOT)
    names = {contract.name for contract in contracts}

    assert "IERC20" in names
    assert "SimpleVault" in names


def test_parse_solidity_file_extracts_contract_state_and_functions():
    contracts = parse_solidity_file(SIMPLE_VAULT, SAMPLE_ROOT)
    vault = _contract_by_name(contracts, "SimpleVault")

    assert vault.path == "src/SimpleVault.sol"
    assert set(vault.state_variables) >= {
        "asset",
        "owner",
        "totalShares",
        "shares",
        "lastClaim",
        "rewardRate",
    }

    function_names = {function.name for function in vault.functions}
    assert function_names >= {
        "setRewardRate",
        "deposit",
        "withdraw",
        "claimRewards",
    }


def test_parse_solidity_file_extracts_visibility_modifiers_and_line_ranges():
    contracts = parse_solidity_file(SIMPLE_VAULT, SAMPLE_ROOT)
    vault = _contract_by_name(contracts, "SimpleVault")

    set_reward_rate = _function_by_name(vault, "setRewardRate")
    deposit = _function_by_name(vault, "deposit")
    withdraw = _function_by_name(vault, "withdraw")
    claim_rewards = _function_by_name(vault, "claimRewards")

    assert set_reward_rate.visibility == "external"
    assert set_reward_rate.modifiers == ["onlyOwner"]

    assert deposit.visibility == "external"
    assert deposit.signature == "deposit(uint256 amount)"
    assert "transferFrom" in deposit.body

    assert withdraw.visibility == "external"
    assert withdraw.signature == "withdraw(uint256 shareAmount)"
    assert "transfer" in withdraw.body

    assert claim_rewards.visibility == "external"
    assert claim_rewards.signature == "claimRewards()"
    assert "lastClaim" in claim_rewards.body

    for function in [set_reward_rate, deposit, withdraw, claim_rewards]:
        assert function.line_start > 0
        assert function.line_end >= function.line_start
