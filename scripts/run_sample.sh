#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
audit-copilot analyze examples/sample_protocol --platform sherlock --out reports/sample
audit-copilot foundry-stubs reports/sample/analysis.json --out reports/sample/foundry
