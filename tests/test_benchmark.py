from pathlib import Path

from audit_copilot.benchmark import (
    BenchmarkFixture,
    benchmark_to_markdown,
    load_benchmark_manifest,
    run_benchmark_manifest,
    run_fixture,
)


ROOT = Path(__file__).parents[1]


def test_run_fixture_matches_expected_prefix():
    fixture = BenchmarkFixture(
        name="sample-vault",
        path=str(ROOT / "examples" / "sample_protocol"),
        expected_hypotheses=["share-manipulation", "reward-insolvency"],
    )

    result = run_fixture(fixture, fixture.path)

    assert result.passed
    assert "share-manipulation" in result.matched_hypotheses
    assert "reward-insolvency" in result.matched_hypotheses
    assert result.forbidden_hypotheses == []


def test_benchmark_markdown_marks_failure():
    fixture = BenchmarkFixture(
        name="sample-vault",
        path=str(ROOT / "examples" / "sample_protocol"),
        expected_hypotheses=["not-a-real-hypothesis"],
    )

    result = run_fixture(fixture, fixture.path)
    markdown = benchmark_to_markdown(type("Summary", (), {
        "passed": 0,
        "failed": 1,
        "total": 1,
        "fixtures": [result],
    })())

    assert not result.passed
    assert "FAIL" in markdown
    assert "not-a-real-hypothesis" in markdown


def test_unexpected_hypotheses_fail_fixture():
    fixture = BenchmarkFixture(
        name="sample-vault",
        path=str(ROOT / "examples" / "sample_protocol"),
        expected_hypotheses=["share-manipulation"],
        unexpected_hypotheses=["reward-insolvency"],
    )

    result = run_fixture(fixture, fixture.path)
    markdown = benchmark_to_markdown(type("Summary", (), {
        "passed": 0,
        "failed": 1,
        "total": 1,
        "fixtures": [result],
    })())

    assert not result.passed
    assert "reward-insolvency" in result.forbidden_hypotheses
    assert "Forbidden" in markdown


def test_benchmark_markdown_includes_health_sections():
    fixture = BenchmarkFixture(
        name="sample-vault",
        path=str(ROOT / "examples" / "sample_protocol"),
        expected_hypotheses=["share-manipulation"],
    )

    result = run_fixture(fixture, fixture.path)
    markdown = benchmark_to_markdown(type("Summary", (), {
        "passed": 1,
        "failed": 0,
        "total": 1,
        "fixtures": [result],
    })())

    assert "## Health summary" in markdown
    assert "## Required / forbidden checks" in markdown
    assert "## Noise watch" in markdown
    assert "## Full observed hypotheses" in markdown
    assert "Positive fixtures" in markdown
    assert "positive" in markdown


def test_expected_hypothesis_prefix_matches_observed_child_id():
    fixture = BenchmarkFixture(
        name="sample-vault",
        path=str(ROOT / "examples" / "sample_protocol"),
        expected_hypotheses=["share-manipulation"],
    )

    result = run_fixture(fixture, fixture.path)

    assert result.passed
    assert result.missing_hypotheses == []
    assert "share-manipulation" in result.matched_hypotheses
    assert any(
        item.startswith("share-manipulation:")
        for item in result.observed_hypotheses
    )


def test_exploit_fixture_manifest_paths_exist():
    fixtures = load_benchmark_manifest(ROOT / "examples" / "exploit_fixtures" / "manifest.json")

    assert fixtures

    manifest_base = ROOT / "examples" / "exploit_fixtures"

    for fixture in fixtures:
        fixture_path = manifest_base / fixture.path
        assert fixture_path.exists(), f"Missing fixture path: {fixture_path}"


def test_exploit_fixture_manifest_passes_required_and_forbidden_checks():
    summary = run_benchmark_manifest(ROOT / "examples" / "exploit_fixtures" / "manifest.json")

    assert summary.total == 14
    assert summary.failed == 0
    assert summary.passed == summary.total
