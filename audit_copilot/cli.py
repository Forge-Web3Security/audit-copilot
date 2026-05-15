from __future__ import annotations

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table
from .engine import analyze_project, write_outputs
from .foundry import write_foundry_stubs
from .models import AnalysisResult, Platform

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


if __name__ == "__main__":
    app()
