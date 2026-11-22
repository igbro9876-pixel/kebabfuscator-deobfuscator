#!/usr/bin/env bash
# Run the full test suite from the project root.
set -euo pipefail
cd "$(dirname "$0")"
python3 -m unittest discover -s tests -v
