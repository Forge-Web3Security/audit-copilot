from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field

from .analysis.hypothesis_engine import generate_hypotheses
from .engine import analyze_project
from .models import Platform


class BenchmarkFixture(BaseModel):
    name: str
    path: str
    expected_hypotheses: list[str] = Field(default_factory=list)
    platform: Platform = Platform.sherlock


class BenchmarkResult(BaseModel):
    name: str
    path: str
    passed: bool
    expected_hypotheses: list[str]
    matched_hypotheses: list[str]
    missing_hypotheses: list[str]
    observed_hypotheses: list[str]


class BenchmarkSummary(BaseModel):
    fixtures: list[BenchmarkResult]

    @property
    def passed(self) -> int:
        return sum(1 for fixture in self.fixtures if fixture.passed)

    @property
    def failed(self) -> int:
        return sum(1 for fixture in self.fixtures if not fixture.passed)

    @property
    def total(self) -> int:
        return len(self.fixtures)


def load_benchmark_manifest(path: str | Path) -> list[BenchmarkFixture]:
    manifest_path = Path(path)
    raw = json.loads(manifest_path.read_text())

    if isinstance(raw, dict):
        fixtures = raw.get("fixtures", [])
    else:
        fixtures = raw

    if not isinstance(fixtures, list):
        raise ValueError("Benchmark manifest must be a list or an object with a fixtures list")

    return [BenchmarkFixture.model_validate(item) for item in fixtures]


def run_benchmark_manifest(path: str | Path) -> BenchmarkSummary:
    manifest_path = Path(path)
    fixtures = load_benchmark_manifest(manifest_path)
    base_dir = manifest_path.parent

    results = []
    for fixture in fixtures:
        fixture_path = Path(fixture.path)
        if not fixture_path.is_absolute():
            fixture_path = base_dir / fixture_path

        results.append(run_fixture(fixture, fixture_path))

    return BenchmarkSummary(fixtures=results)


def run_fixture(fixture: BenchmarkFixture, fixture_path: str | Path) -> BenchmarkResult:
    result = analyze_project(fixture_path, fixture.platform)
    analysis_payload = json.loads(result.model_dump_json())
    hypotheses = generate_hypotheses(analysis_payload)
    observed = sorted({h.id for h in hypotheses})

    matched: list[str] = []
    missing: list[str] = []

    for expected in fixture.expected_hypotheses:
        if _matches_expected(expected, observed):
            matched.append(expected)
        else:
            missing.append(expected)

    return BenchmarkResult(
        name=fixture.name,
        path=str(fixture_path),
        passed=not missing,
        expected_hypotheses=fixture.expected_hypotheses,
        matched_hypotheses=matched,
        missing_hypotheses=missing,
        observed_hypotheses=observed,
    )


def benchmark_to_markdown(summary: BenchmarkSummary) -> str:
    lines = [
        "# Audit Copilot Benchmark Results",
        "",
        f"- **Passed:** {summary.passed}",
        f"- **Failed:** {summary.failed}",
        f"- **Total:** {summary.total}",
        "",
        "| Fixture | Status | Matched | Missing |",
        "|---|---:|---|---|",
    ]

    for result in summary.fixtures:
        status = "PASS" if result.passed else "FAIL"
        matched = ", ".join(result.matched_hypotheses) if result.matched_hypotheses else "-"
        missing = ", ".join(result.missing_hypotheses) if result.missing_hypotheses else "-"
        lines.append(f"| {result.name} | {status} | {matched} | {missing} |")

    lines.append("")
    lines.append("## Observed hypotheses")
    lines.append("")

    for result in summary.fixtures:
        lines.append(f"### {result.name}")
        if result.observed_hypotheses:
            lines.extend([f"- `{item}`" for item in result.observed_hypotheses])
        else:
            lines.append("- No hypotheses generated")
        lines.append("")

    return "\n".join(lines)


def _matches_expected(expected: str, observed: list[str]) -> bool:
    """Match exact IDs or prefixes.

    Examples:
    - external-call-order matches external-call-order:simplevault-withdraw
    - reward-insolvency:simplevault-claimrewards matches exactly
    """
    expected_lower = expected.lower()
    return any(
        item.lower() == expected_lower or item.lower().startswith(expected_lower + ":")
        for item in observed
    )
