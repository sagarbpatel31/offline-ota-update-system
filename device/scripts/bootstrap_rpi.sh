#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

python3 -m venv "${PROJECT_ROOT}/.venv"
source "${PROJECT_ROOT}/.venv/bin/activate"
pip install -r "${PROJECT_ROOT}/requirements.txt"

"${PROJECT_ROOT}/device/scripts/install_rpi_services.sh" "${PROJECT_ROOT}"

echo "Bootstrap complete."
