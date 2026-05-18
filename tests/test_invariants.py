from pathlib import Path

from audit_copilot.engine import analyze_project
from audit_copilot.invariants import generate_invariants
from audit_copilot.models import Platform
from audit_copilot.solidity_parser import collect_contracts
from audit_copilot.modeler import build_protocol_model
from audit_copilot.transitions import extract_transitions


ROOT = Path(__file__).parents[1]
SAMPLE_ROOT = ROOT / "examples" / "sample_protocol"
CEI_SAFE_ROOT = ROOT / "examples" / "exploit_fixtures" / "negative" / "cei_safe_withdraw"


def _categories(invariants):
    return {invariant.category for invariant in invariants}


def _invariant_by_category(invariants, category: str):
    return next(invariant for invariant in invariants if invariant.category == category)


def test_generate_invariants_for_sample_vault_core_categories():
    result = analyze_project(SAMPLE_ROOT, Platform.sherlock)

    categories = _categories(result.invariants)

    assert "accounting" in categories
    assert "asset-flow" in categories
    assert "temporal" in categories
    assert "access-control" in categories


def test_generate_invariants_links_asset_flow_to_value_moving_functions():
    result = analyze_project(SAMPLE_ROOT, Platform.sherlock)

    asset_flow = _invariant_by_category(result.invariants, "asset-flow")

    assert asset_flow.related_contracts == ["SimpleVault"]
    assert set(asset_flow.related_functions) >= {
        "SimpleVault.deposit",
        "SimpleVault.withdraw",
        "SimpleVault.claimRewards",
    }
    assert "caller" in " ".join(asset_flow.attack_questions).lower()
    assert "handler" in asset_flow.foundry_hint.lower()


def test_generate_invariants_links_privileged_controls_without_marking_all_functions_privileged():
    result = analyze_project(SAMPLE_ROOT, Platform.sherlock)

    access_control = _invariant_by_category(result.invariants, "access-control")

    assert access_control.related_contracts == ["SimpleVault"]
    assert access_control.related_functions == ["SimpleVault.setRewardRate"]
    assert access_control.category == "access-control"
    assert any("admin" in note.lower() for note in access_control.attack_questions)


def test_generate_invariants_for_native_eth_fixture_has_asset_flow_without_temporal_or_access_control():
    contracts = collect_contracts(CEI_SAFE_ROOT)
    transitions = extract_transitions(contracts)
    model = build_protocol_model(CEI_SAFE_ROOT, contracts)

    invariants = generate_invariants(model, transitions)
    categories = _categories(invariants)

    assert "asset-flow" in categories
    assert "temporal" not in categories
    assert "access-control" not in categories

    asset_flow = _invariant_by_category(invariants, "asset-flow")
    assert asset_flow.related_contracts == ["CeiSafeWithdraw"]
    assert set(asset_flow.related_functions) == {
        "CeiSafeWithdraw.deposit",
        "CeiSafeWithdraw.withdraw",
    }


def test_generate_invariants_falls_back_to_state_machine_when_no_signals():
    class EmptyModel:
        contracts = []
        accounting_systems = []
        integrations = []

    invariants = generate_invariants(EmptyModel(), [])

    assert len(invariants) == 1
    assert invariants[0].id == "INV-001"
    assert invariants[0].category == "state-machine"
