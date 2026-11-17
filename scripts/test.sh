#!/usr/bin/env bash
# Run the test suite in a local virtualenv (.venv).
set -euo pipefail
cd "$(dirname "$0")/.."

if [[ ! -d .venv ]]; then
  python3 -m venv .venv
fi
# shellcheck disable=SC1091
source .venv/bin/activate
pip install -q -r requirements-dev.txt
python -m pytest -q "$@"
