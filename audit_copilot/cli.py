from __future__ import annotations

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from .engine import analyze_project, write_outputs
from .foundry import write_foundry_stubs
from .foundry_plan import write_foundry_plan_from_analysis
from .models import AnalysisResult, Platform
from .benchmark import benchmark_to_markdown, run_benchmark_manifest
from .invariant_breaker import (
    break_invariant_plan,
    break_plan_to_markdown,
    invariants_to_markdown,
    load_analysis as load_analysis_json,
    propose_invariants_from_analysis,
)
from .session import (
    add_invariant as add_context_invariant,
    add_note as add_context_note,
    confirm_attack_vector as confirm_context_attack_vector,
    context_summary,
    load_audit_context,
    mark_invalid as mark_context_invalid,
)
from .ai_agent import (
    generate_agent_prompt,
    hypotheses_to_findings,
)
from .reporting_cyfrin import (
    write_cyfrin_report,
    write_threat_model,
)

app = typer.Typer(help="Invariant-first smart contract audit copilot")
console = Console()


@app.command()
def analyze(
    root: Path = typer.Argument(..., exists=True, file_okay=False, dir_okay=True),
    platform: Platform = typer.Option(Platform.generic, help="Contest/reporting style mode"),
    out: Path = typer.Option(Path("reports/analysis"), help="Output directory"),
    slither: Path | None = typer.Option(None, help="Optional Slither JSON output"),
    aderyn: Path | None = typer.Option(None, help="Optional Aderyn JSON output"),
    mythril: Path | None = typer.Option(None, help="Optional Mythril JSON output"),
    context: Path | None = typer.Option(None, help="Optional project-local audit_context.json"),
):
    """Analyze a Solidity project and produce model, invariants, findings, and report."""
    result = analyze_project(root, platform, str(slither) if slither else None, str(aderyn) if aderyn else None, str(mythril) if mythril else None)
    write_outputs(result, out, context)

    table = Table(title="Audit Copilot Summary")
    table.add_column("Metric")
    table.add_column("Count", justify="right")
    table.add_row("Contracts", str(len(result.model.contracts)))
    table.add_row("Transitions", str(len(result.transitions)))
    table.add_row("Invariants", str(len(result.invariants)))
    table.add_row("Scanner signals", str(len(result.scanner_signals)))
    table.add_row("Finding candidates", str(len(result.findings)))
    console.print(table)
    console.print(f"[green]Wrote:[/green] {out / 'analysis.json'}")
    console.print(f"[green]Wrote:[/green] {out / 'report.md'}")
    console.print(f"[green]Wrote:[/green] {out / 'hypotheses.json'}")
    console.print(f"[green]Wrote:[/green] {out / 'hypotheses.md'}")
    if slither:
        console.print(f"[green]Loaded Slither signals:[/green] {slither}")
    if aderyn:
        console.print(f"[green]Loaded Aderyn signals:[/green] {aderyn}")
    if mythril:
        console.print(f"[green]Loaded Mythril signals:[/green] {mythril}")
    if context:
        console.print(f"[green]Used context:[/green] {context}")


@app.command("foundry-stubs")
def foundry_stubs(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    out: Path = typer.Option(Path("reports/foundry-stubs"), help="Output directory"),
):
    """Generate Foundry invariant and PoC test skeletons from analysis.json."""
    result = AnalysisResult.model_validate_json(analysis_json.read_text())
    write_foundry_stubs(result, out)
    console.print(f"[green]Wrote Foundry stubs to:[/green] {out}")





@app.command("benchmark-fixtures")
def benchmark_fixtures_command(
    manifest: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    out: Path | None = typer.Option(None, help="Optional markdown output path"),
):
    """Run benchmark fixtures and compare observed hypotheses to expected IDs/prefixes."""
    summary = run_benchmark_manifest(manifest)
    markdown = benchmark_to_markdown(summary)

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown)
        console.print(f"[green]Wrote benchmark report:[/green] {out}")
    else:
        console.print(markdown)

    if summary.failed:
        raise typer.Exit(code=1)



@app.command("foundry-plan")
def foundry_plan_command(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    invariant: str = typer.Argument(..., help="Invariant to turn into a Foundry test skeleton"),
    out: Path = typer.Option(Path("reports/foundry/GeneratedInvariantPlan.t.sol"), help="Output Solidity test path"),
    contract_name: str = typer.Option("GeneratedInvariantPlanTest", help="Generated Solidity test contract name"),
):
    """Generate a Foundry test skeleton from an invariant break plan."""
    written = write_foundry_plan_from_analysis(
        analysis_json=analysis_json,
        invariant=invariant,
        out=out,
        contract_name=contract_name,
    )
    console.print(f"[green]Wrote Foundry plan:[/green] {written}")



@app.command("propose-invariants")
def propose_invariants_command(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    out: Path | None = typer.Option(None, help="Optional markdown output path"),
):
    """Propose important invariants from analysis.json."""
    analysis = load_analysis_json(analysis_json)
    invariants = propose_invariants_from_analysis(analysis)
    markdown = invariants_to_markdown(invariants)

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown)
        console.print(f"[green]Wrote:[/green] {out}")
    else:
        console.print(markdown)


@app.command("break-invariant")
def break_invariant_command(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    invariant: str = typer.Argument(..., help="Invariant to attempt to break"),
    out: Path | None = typer.Option(None, help="Optional markdown output path"),
):
    """Generate attack plans for breaking a specific invariant."""
    analysis = load_analysis_json(analysis_json)
    plan = break_invariant_plan(analysis, invariant)
    markdown = break_plan_to_markdown(plan)

    if out:
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(markdown)
        console.print(f"[green]Wrote:[/green] {out}")
    else:
        console.print(markdown)



@app.command("mark-invalid")
def mark_invalid_command(
    context: Path = typer.Argument(..., help="Path to audit_context.json"),
    hypothesis_id: str = typer.Argument(..., help="Hypothesis ID to suppress in this audit"),
    reason: str = typer.Argument(..., help="Why this hypothesis is invalid"),
):
    """Record a human false-positive judgment for this audit."""
    audit_context = mark_context_invalid(context, hypothesis_id, reason)
    summary = context_summary(audit_context)
    console.print(f"[green]Marked invalid:[/green] {hypothesis_id}")
    console.print(f"[green]Context:[/green] {context}")
    console.print(summary)


@app.command("confirm-vector")
def confirm_vector_command(
    context: Path = typer.Argument(..., help="Path to audit_context.json"),
    pattern: str = typer.Argument(..., help="Pattern or hypothesis prefix to prioritize"),
    reason: str = typer.Argument(..., help="Why this attack vector is relevant"),
):
    """Record a human-confirmed attack vector for this audit."""
    audit_context = confirm_context_attack_vector(context, pattern, reason)
    summary = context_summary(audit_context)
    console.print(f"[green]Confirmed vector:[/green] {pattern}")
    console.print(f"[green]Context:[/green] {context}")
    console.print(summary)


@app.command("add-invariant")
def add_invariant_command(
    context: Path = typer.Argument(..., help="Path to audit_context.json"),
    invariant: str = typer.Argument(..., help="Custom invariant to track"),
):
    """Add a human-defined invariant for this audit."""
    audit_context = add_context_invariant(context, invariant)
    summary = context_summary(audit_context)
    console.print("[green]Added invariant:[/green]")
    console.print(invariant)
    console.print(f"[green]Context:[/green] {context}")
    console.print(summary)


@app.command("add-note")
def add_note_command(
    context: Path = typer.Argument(..., help="Path to audit_context.json"),
    note: str = typer.Argument(..., help="Audit note to store"),
):
    """Add a general audit note to the project-local context."""
    audit_context = add_context_note(context, note)
    summary = context_summary(audit_context)
    console.print("[green]Added note:[/green]")
    console.print(note)
    console.print(f"[green]Context:[/green] {context}")
    console.print(summary)


@app.command("show-context")
def show_context_command(
    context: Path = typer.Argument(..., help="Path to audit_context.json"),
):
    """Show the current project-local audit context."""
    audit_context = load_audit_context(context)
    console.print_json(audit_context.model_dump_json())


@app.command("agent-prompt")
def agent_prompt_command(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    platform: Platform = typer.Option(Platform.sherlock, help="Contest platform"),
):
    """Generate an AI agent prompt from analysis.json for assisted auditing."""
    analysis = load_analysis_json(analysis_json)
    result = AnalysisResult.model_validate(analysis)
    from .analysis.hypothesis_engine import generate_hypotheses
    hypotheses = generate_hypotheses(analysis)
    prompt = generate_agent_prompt(result, hypotheses, platform.value)
    console.print(prompt)


@app.command("cyfrin-report")
def cyfrin_report_command(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    out: Path = typer.Option(Path("reports/cyfrin-report.md"), help="Output report path"),
    platform: Platform = typer.Option(Platform.sherlock, help="Contest platform"),
):
    """Generate a Cyfrin-format audit report from analysis.json."""
    analysis = load_analysis_json(analysis_json)
    result = AnalysisResult.model_validate(analysis)
    from .analysis.hypothesis_engine import generate_hypotheses
    hypotheses = generate_hypotheses(analysis)
    findings_data = hypotheses_to_findings(hypotheses, analysis)
    written = write_cyfrin_report(result, hypotheses, out, platform.value, findings_data)
    console.print(f"[green]Wrote Cyfrin report:[/green] {written}")


@app.command("threat-model")
def threat_model_command(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    out: Path = typer.Option(Path("reports/threat-model.md"), help="Output threat model path"),
):
    """Generate a threat model document from analysis.json."""
    analysis = load_analysis_json(analysis_json)
    result = AnalysisResult.model_validate(analysis)
    written = write_threat_model(result, out)
    console.print(f"[green]Wrote threat model:[/green] {written}")


if __name__ == "__main__":
    app()
