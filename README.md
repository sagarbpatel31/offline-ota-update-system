# Offline OTA Update System

Local-first OTA update system for Linux edge devices with signed update bundles, staged installs, health checks, and automatic rollback.

## Goals

- Support offline update delivery over USB and local HTTP
- Verify bundle integrity and authenticity before install
- Stage releases safely and promote only after health validation
- Roll back automatically when an update fails
- Provide a simple local dashboard for status and audit history

## MVP Scope

- App-level OTA updates for a demo service
- Signed manifest verification
- Staged release directories with symlink switching
- Health-check based promotion and rollback
- Local dashboard with update history

## Repository Layout

- `agent/` device updater daemon and state machine
- `demo_service/` Raspberry Pi demo app and release builder
- `server/` local dashboard and API
- `signer/` bundle manifest and signing tool
- `device/` install scripts and systemd units
- `docs/` architecture, roadmap, and demo flow
- `manifests/` sample update metadata

## Planned Workflow

1. Build a release bundle with manifest and signatures
2. Deliver bundle over USB or local HTTP
3. Device agent validates version, target, hashes, and signature
4. Agent stages release to inactive location
5. Agent switches active release and restarts service
6. Health checks confirm success or trigger rollback

## Getting Started

### Python

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Generate signing keys

```bash
python -m signer.main generate-keys
```

### Build and sign a bundle manifest

```bash
python -m demo_service.build_release 1.1.0
python -m signer.main build-manifest artifacts/bundle 1.1.0
python -m signer.main build-bundle-index manifests/bundle.manifest.json --output bundle-index.json --release-notes "Improved diagnostics"
python -m signer.main sign-bundle manifests/bundle.manifest.json
```

### Verify a signed bundle

```bash
python -m agent.main verify
```

### Install a signed bundle

```bash
python -m agent.main init-layout
python -m agent.main install --activate-command "systemctl restart offline-ota-demo.service"
```

### Discover bundles from USB or local HTTP

```bash
python -m agent.main discover-usb --mount-root /media
python -m agent.main discover-http http://192.168.1.50:8081/
python -m agent.main list-discovered
python -m agent.main select-latest
python -m agent.main install-discovered --index 0 --activate-command "systemctl restart offline-ota-demo.service"
python -m agent.main install-latest --activate-command "systemctl restart offline-ota-demo.service"
```

Discovered candidates include compatibility flags and policy reasons. Incompatible bundles are rejected before staging.

### Run unattended polling

```bash
python -m agent.main poll-once
python -m agent.main poll-loop --interval-seconds 60
```

### Inspect device status and update history

```bash
python -m agent.main device-status
python -m agent.main audit-summary
curl http://127.0.0.1:8000/api/status
curl http://127.0.0.1:8000/api/history
curl http://127.0.0.1:8000/api/service
curl http://127.0.0.1:8000/api/discovered
curl http://127.0.0.1:8000/api/discovered/latest
curl http://127.0.0.1:8000/api/audit/attempts
curl http://127.0.0.1:8000/api/audit/policy
curl http://127.0.0.1:8000/api/audit/summary
```

### Run the local dashboard

```bash
uvicorn server.main:app --reload
```

### Run the Raspberry Pi demo service

```bash
uvicorn demo_service.app:app --host 0.0.0.0 --port 8080
```

### Raspberry Pi activation hook

```bash
export OFFLINE_OTA_ACTIVATE_COMMAND="systemctl restart offline-ota-demo.service"
```

### Raspberry Pi bootstrap

```bash
chmod +x device/scripts/bootstrap_rpi.sh device/scripts/install_rpi_services.sh
sudo device/scripts/bootstrap_rpi.sh
sudo systemctl start offline-ota-demo.service offline-ota-dashboard.service offline-ota-agent.service
```

Edit `/etc/offline-ota/offline-ota.env` to set `OFFLINE_OTA_HTTP_SOURCES`, USB mount roots, and poll interval.

## Current Status

This repository is scaffolded for MVP implementation. The current code provides:

- basic project structure
- Ed25519 key generation, manifest hashing, and bundle signing
- bundle verification against artifact hashes and public key
- staged install copying, active symlink promotion, and rollback primitives
- health-check-driven install flow with JSON state tracking
- Raspberry Pi demo service with release-aware metadata
- USB and local HTTP bundle discovery with cached candidates
- device-model, minimum-agent-version, and anti-downgrade policy checks
- latest-compatible bundle selection with optional release notes metadata
- Raspberry Pi polling loop and bootstrap scripts for unattended updates
- structured audit summaries for attempts, policy rejections, and selection flow
- starter FastAPI dashboard
- starter agent CLI
- systemd service skeleton

## Next Milestones

- Add rollout policy and background scheduling
- Add richer update attempt reporting in the dashboard
- Add channel/ring controls for stable vs canary rollout
