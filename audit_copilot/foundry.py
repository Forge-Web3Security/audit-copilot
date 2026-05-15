from __future__ import annotations

from pathlib import Path
from .models import AnalysisResult, FindingCandidate, InvariantCandidate


def sanitize(name: str) -> str:
    return "".join(ch if ch.isalnum() else "_" for ch in name).strip("_")


def invariant_test_stub(inv: InvariantCandidate) -> str:
    test_name = sanitize(inv.id + "_" + inv.title)[:80]
    comments = "\n    ".join([f"// - {q}" for q in inv.attack_questions])
    hint = f"// Foundry hint: {inv.foundry_hint}" if inv.foundry_hint else "// Fill in protocol-specific setup and handlers."
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract {test_name}Test is Test {{
    function setUp() public {{
        // TODO: deploy protocol, mint assets, set roles, seed balances.
    }}

    function invariant_{sanitize(inv.id)}() public {{
        {hint}
        {comments}
        // TODO: assert invariant condition here.
        assertTrue(true);
    }}
}}
'''


def poc_test_stub(finding: FindingCandidate) -> str:
    test_name = sanitize(finding.id + "_PoC")
    steps = "\n        ".join([f"// - {s}" for s in finding.next_validation_steps])
    return f'''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";

contract {test_name}Test is Test {{
    address attacker = address(0xA11CE);
    address victim = address(0xB0B);

    function setUp() public {{
        // TODO: deploy protocol and configure realistic initial state.
    }}

    function test_{sanitize(finding.id)}_exploitPath() public {{
        // Hypothesis: {finding.hypothesis}
        {steps}

        vm.startPrank(attacker);
        // TODO: manipulate state.
        // TODO: trigger vulnerable transition.
        vm.stopPrank();

        // TODO: assert material impact: attacker profit, victim loss, accounting break, or invariant violation.
        assertTrue(true);
    }}
}}
'''


def write_foundry_stubs(result: AnalysisResult, out: str | Path) -> None:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    inv_dir = out / "invariants"
    poc_dir = out / "pocs"
    inv_dir.mkdir(exist_ok=True)
    poc_dir.mkdir(exist_ok=True)

    for inv in result.invariants:
        (inv_dir / f"{sanitize(inv.id)}.t.sol").write_text(invariant_test_stub(inv), encoding="utf-8")
    for finding in result.findings[:20]:
        (poc_dir / f"{sanitize(finding.id)}.t.sol").write_text(poc_test_stub(finding), encoding="utf-8")
