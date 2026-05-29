#!/usr/bin/env bash
set -euo pipefail

PROJECT_ROOT="${1:-/opt/offline-ota}"
ENV_DIR="/etc/offline-ota"

mkdir -p "${PROJECT_ROOT}/artifacts/device" "${PROJECT_ROOT}/artifacts/discovery" "${ENV_DIR}"

if [[ ! -f "${ENV_DIR}/offline-ota.env" ]]; then
  cp "${PROJECT_ROOT}/device/config/offline-ota.env.example" "${ENV_DIR}/offline-ota.env"
fi

cp "${PROJECT_ROOT}/device/systemd/offline-ota-agent.service" /etc/systemd/system/offline-ota-agent.service
cp "${PROJECT_ROOT}/device/systemd/offline-ota-dashboard.service" /etc/systemd/system/offline-ota-dashboard.service
cp "${PROJECT_ROOT}/device/systemd/offline-ota-demo.service" /etc/systemd/system/offline-ota-demo.service

systemctl daemon-reload
systemctl enable offline-ota-demo.service
systemctl enable offline-ota-dashboard.service
systemctl enable offline-ota-agent.service

echo "Installed systemd units. Edit ${ENV_DIR}/offline-ota.env before starting services."

