from pathlib import Path
from audit_copilot.engine import analyze_project
from audit_copilot.models import Platform


def test_sample_protocol_generates_model_and_findings():
    root = Path(__file__).parents[1] / "examples" / "sample_protocol"
    result = analyze_project(root, Platform.sherlock)
    assert result.model.contracts
    assert result.transitions
    assert result.invariants
    assert result.findings
    assert any("asset" in inv.category or "accounting" in inv.category for inv in result.invariants)
