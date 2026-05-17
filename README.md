# Audit Copilot

An invariant-first smart contract audit copilot starter kit.

This is not another "run scanners and paste warnings" tool. The pipeline is designed around the competitive audit workflow:

```text
Pattern Detection
        ↓
Protocol Modeling
        ↓
Invariant Extraction
        ↓
Economic Reasoning
        ↓
Exploit Simulation Planning
        ↓
Contest-Aware Reporting
```

## What it does now

- Indexes Solidity source files from a repo or folder.
- Builds a rough protocol model:
  - contracts
  - actors / roles
  - assets
  - integrations
  - trust assumptions
  - accounting hints
- Extracts state transitions:
  - function name
  - visibility
  - modifiers
  - reads/writes hints
  - external calls
  - asset movement hints
  - authorization hints
- Generates candidate invariants.
- Imports scanner signals from Slither/Aderyn JSON when available.
- Filters findings using contest-validity logic.
- Creates Foundry PoC/invariant test stubs.
- Generates markdown audit notes and report drafts.

## Install

```bash
cd audit-copilot
python -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

Analyze a Solidity project:

```bash
audit-copilot analyze /path/to/project --platform sherlock --out reports/project-analysis
```

Generate Foundry test stubs from the analysis:

```bash
audit-copilot foundry-stubs reports/project-analysis/analysis.json --out reports/project-analysis/foundry
```

Run against the included sample:

```bash
audit-copilot analyze examples/sample_protocol --platform sherlock --out reports/sample
```

## Optional scanner integration

Run scanners separately and feed their JSON output into the copilot:

```bash
slither /path/to/project --json slither.json
audit-copilot analyze /path/to/project --slither slither.json --out reports/project-analysis
```

Aderyn support is intentionally simple right now; pass a JSON file containing findings:

```bash
audit-copilot analyze /path/to/project --aderyn aderyn.json --out reports/project-analysis
```

## Philosophy

Scanner findings are only signals. The valuable layer is reasoning about:

- exploitability
- protocol invariants
- state-machine manipulation
- economic abuse
- accounting drift
- permissionless repeatability
- realistic impact

## Project status

Starter architecture. It is built to be extended, not blindly trusted.
