from __future__ import annotations

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from .engine import analyze_project, write_outputs
from .foundry import write_foundry_stubs
from .models import AnalysisResult, Platform
from .session import (
    add_invariant as add_context_invariant,
    add_note as add_context_note,
    confirm_attack_vector as confirm_context_attack_vector,
    context_summary,
    load_audit_context,
    mark_invalid as mark_context_invalid,
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
):
    """Analyze a Solidity project and produce model, invariants, findings, and report."""
    result = analyze_project(root, platform, str(slither) if slither else None, str(aderyn) if aderyn else None)
    write_outputs(result, out)

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


@app.command("foundry-stubs")
def foundry_stubs(
    analysis_json: Path = typer.Argument(..., exists=True, file_okay=True, dir_okay=False),
    out: Path = typer.Option(Path("reports/foundry-stubs"), help="Output directory"),
):
    """Generate Foundry invariant and PoC test skeletons from analysis.json."""
    result = AnalysisResult.model_validate_json(analysis_json.read_text())
    write_foundry_stubs(result, out)
    console.print(f"[green]Wrote Foundry stubs to:[/green] {out}")


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


if __name__ == "__main__":
    app()
