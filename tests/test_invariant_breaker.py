import json
from pathlib import Path

from audit_copilot.engine import analyze_project
from audit_copilot.invariant_breaker import (
    break_invariant_plan,
    propose_invariants_from_analysis,
)
from audit_copilot.models import Platform


def test_propose_invariants_from_sample_protocol():
    result = analyze_project("examples/sample_protocol", Platform.sherlock)
    analysis = json.loads(result.model_dump_json())

    invariants = propose_invariants_from_analysis(analysis)
    ids = {item.id for item in invariants}

    assert "shares-redeemable" in ids
    assert "rewards-do-not-drain-principal" in ids
    assert "actual-assets-match-accounting" in ids


def test_break_reward_solvency_invariant_plan():
    result = analyze_project("examples/sample_protocol", Platform.sherlock)
    analysis = json.loads(result.model_dump_json())

    plan = break_invariant_plan(
        analysis,
        "Reward claims must not make total redeemable shares exceed asset balance",
    )

    assert "Reward reserve insolvency" in plan.likely_attack_classes
    assert any("claim" in idea.lower() for idea in plan.foundry_test_ideas)
    assert plan.attack_sequences
