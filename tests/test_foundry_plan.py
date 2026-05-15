from audit_copilot.foundry_plan import (
    render_foundry_test_skeleton,
    foundry_test_name_from_invariant,
)
from audit_copilot.invariant_breaker import InvariantBreakPlan


def test_foundry_test_name_from_reward_invariant():
    assert (
        foundry_test_name_from_invariant(
            "Reward claims must not make total redeemable shares exceed asset balance"
        )
        == "test_invariant_rewardClaimsDoNotDrainPrincipal"
    )


def test_render_foundry_test_skeleton_contains_attack_plan():
    plan = InvariantBreakPlan(
        invariant="Reward claims must not make total redeemable shares exceed asset balance",
        likely_attack_classes=["Reward reserve insolvency"],
        preconditions=["Rewards are paid from principal reserves."],
        attack_sequences=[
            [
                "Actor A deposits.",
                "Warp time.",
                "Actor A claims rewards.",
                "Actor B withdraws.",
            ]
        ],
        foundry_test_ideas=["test_invariant_rewardClaimsDoNotDrainPrincipal()"],
        evidence_to_collect=["Vault asset balance after claims."],
        contest_validity_notes=["Escalate only with fund loss."],
    )

    rendered = render_foundry_test_skeleton(plan)

    assert "contract GeneratedInvariantPlanTest is Test" in rendered
    assert "test_invariant_rewardClaimsDoNotDrainPrincipal" in rendered
    assert "Reward reserve insolvency" in rendered
    assert "Vault asset balance after claims." in rendered
