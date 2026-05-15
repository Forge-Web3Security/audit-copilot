from audit_copilot.benchmark import (
    BenchmarkFixture,
    benchmark_to_markdown,
    run_fixture,
)


def test_run_fixture_matches_expected_prefix():
    fixture = BenchmarkFixture(
        name="sample-vault",
        path="examples/sample_protocol",
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
        path="examples/sample_protocol",
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
        path="examples/sample_protocol",
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
