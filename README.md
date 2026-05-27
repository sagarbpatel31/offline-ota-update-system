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

### Run the local dashboard

```bash
uvicorn server.main:app --reload
```

### Run the agent stub

```bash
python -m agent.main status
```

## Current Status

This repository is scaffolded for MVP implementation. The current code provides:

- basic project structure
- starter FastAPI dashboard
- starter agent CLI
- sample manifest format
- systemd service skeleton

## Next Milestones

- Implement signed bundle creation and verification
- Add staged install and symlink-based release switching
- Add post-install health checks and rollback state machine
- Add USB and local HTTP bundle discovery
- Add update audit log and dashboard views

