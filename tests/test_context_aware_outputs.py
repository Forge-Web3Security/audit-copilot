import json
from pathlib import Path

from audit_copilot.engine import analyze_project, write_outputs
from audit_copilot.models import Platform
from audit_copilot.session import confirm_attack_vector, mark_invalid


def test_write_outputs_applies_audit_context(tmp_path: Path):
    context_path = tmp_path / "audit_context.json"
    out = tmp_path / "out"

    mark_invalid(
        context_path,
        "privilege-review:simplevault-setrewardrate",
        "Admin-only setter is trusted in this audit context",
    )
    confirm_attack_vector(
        context_path,
        "reward-insolvency",
        "Rewards are paid from principal reserves",
    )

    result = analyze_project("examples/sample_protocol", Platform.sherlock)
    write_outputs(result, out, context_path)

    hypotheses = json.loads((out / "hypotheses.json").read_text())
    ids = {item["id"] for item in hypotheses}

    assert "privilege-review:simplevault-setrewardrate" not in ids

    reward = next(
        item for item in hypotheses
        if item["id"] == "reward-insolvency:simplevault-claimrewards"
    )
    assert reward["confidence"] > 0.60
