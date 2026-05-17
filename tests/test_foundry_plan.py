from audit_copilot.foundry_plan import (
    extract_protocol_context,
    foundry_test_name_from_invariant,
    render_foundry_test_skeleton,
)
from audit_copilot.invariant_breaker import InvariantBreakPlan


def _analysis():
    return {
        "transitions": [
            {
                "contract": "SimpleVault",
                "function": "deposit",
                "reads_storage": ["amount", "asset"],
                "writes_storage": ["assetsBefore", "minted", "shares", "totalShares"],
                "external_calls": ["transferFrom"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "claimRewards",
                "reads_storage": ["asset", "rewardRate", "shares"],
                "writes_storage": ["amount", "elapsed", "lastClaim"],
                "external_calls": ["transfer"],
                "auth_requirements": [],
                "asset_movements": ["token movement/mint/burn"],
            },
            {
                "contract": "SimpleVault",
                "function": "setRewardRate",
                "reads_storage": [],
                "writes_storage": ["rewardRate"],
                "external_calls": [],
                "auth_requirements": ["onlyOwner"],
                "asset_movements": [],
            },
        ]
    }


def test_foundry_test_name_from_reward_invariant():
    assert (
        foundry_test_name_from_invariant(
            "Reward claims must not make total redeemable shares exceed asset balance"
        )
        == "test_invariant_rewardClaimsDoNotDrainPrincipal"
    )


def test_extract_protocol_context_detects_relevant_functions_and_admin_actor():
    context = extract_protocol_context(
        _analysis(),
        "Reward claims must not make total redeemable shares exceed asset balance",
    )

    fq_names = {fn["fq_name"] for fn in context["relevant_functions"]}
    actors = {actor["name"] for actor in context["actors"]}

    assert "SimpleVault.deposit" in fq_names
    assert "SimpleVault.claimRewards" in fq_names
    assert "SimpleVault.setRewardRate" in fq_names
    assert "admin" in actors
    assert "rewardRate" in context["state_terms"]


def test_render_foundry_test_skeleton_contains_protocol_context():
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

    rendered = render_foundry_test_skeleton(plan, analysis=_analysis())

    assert "Detected contracts:" in rendered
    assert "SimpleVault internal simpleVault;" in rendered
    assert "address internal admin" in rendered
    assert "TODO: wire call to SimpleVault.claimRewards" in rendered
    assert "vm.prank(actorA); call SimpleVault.claimRewards" in rendered
    assert "State terms:" in rendered
