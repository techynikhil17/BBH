#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV="$PROJECT_DIR/venv"

if [ ! -d "$VENV" ]; then
    echo "ERROR: venv not found at $VENV. Run setup_env.sh first."
    exit 1
fi

source "$VENV/bin/activate"

LIMIT="${LIMIT:-500}"
SOURCES="${SOURCES:-all}"

cd "$PROJECT_DIR"

if [ "$SOURCES" = "all" ]; then
    python -m collector.main collect --limit "$LIMIT"
else
    # Split space-separated sources into --sources flags
    ARGS=()
    for src in $SOURCES; do
        ARGS+=("--sources" "$src")
    done
    python -m collector.main collect "${ARGS[@]}" --limit "$LIMIT"
fi
