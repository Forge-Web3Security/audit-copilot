from pathlib import Path

from audit_copilot.session import (
    add_invariant,
    apply_context_to_hypotheses,
    confirm_attack_vector,
    load_audit_context,
    mark_invalid,
)


def test_audit_context_round_trip(tmp_path: Path):
    path = tmp_path / "audit_context.json"

    mark_invalid(path, "price-manipulation:demo", "No oracle path exists")
    confirm_attack_vector(path, "reward-insolvency", "Rewards are paid from principal")
    add_invariant(path, "All shares remain redeemable after reward claims")

    context = load_audit_context(path)

    assert context.invalidated_hypotheses[0].id == "price-manipulation:demo"
    assert context.confirmed_attack_vectors[0].pattern == "reward-insolvency"
    assert context.custom_invariants == [
        "All shares remain redeemable after reward claims"
    ]


def test_context_filters_invalid_hypotheses_and_boosts_confirmed_patterns(tmp_path: Path):
    path = tmp_path / "audit_context.json"
    mark_invalid(path, "price-manipulation:demo", "No oracle path exists")
    confirm_attack_vector(path, "reward-insolvency", "Relevant to this vault")

    context = load_audit_context(path)

    hypotheses = [
        {"id": "price-manipulation:demo", "confidence": 0.9},
        {"id": "reward-insolvency:vault-claim", "confidence": 0.5},
        {"id": "share-manipulation:vault-deposit", "confidence": 0.6},
    ]

    filtered = apply_context_to_hypotheses(hypotheses, context)
    ids = [h["id"] for h in filtered]

    assert "price-manipulation:demo" not in ids
    assert "reward-insolvency:vault-claim" in ids
    boosted = next(h for h in filtered if h["id"] == "reward-insolvency:vault-claim")
    assert boosted["confidence"] > 0.5
