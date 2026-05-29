from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi import FastAPI

from demo_service.app import service_metadata
from ota.discovery import select_latest_compatible
from ota.release import (
    ReleaseLayout,
    active_version,
    find_attempt,
    read_history,
    summarize_attempts,
    summarize_policy_events,
    summarize_selection_events,
)
from ota.state import DeviceStateStore


app = FastAPI(title="Offline OTA Dashboard", version="0.1.0")
STATE_STORE = DeviceStateStore(Path("artifacts/device-state.json"))
LAYOUT = ReleaseLayout(Path("artifacts/device"))


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/status")
def status() -> dict[str, object]:
    payload = STATE_STORE.load()
    payload["active_version"] = active_version(LAYOUT) or payload["active_version"]
    payload["last_checked_at"] = payload["last_checked_at"] or datetime.now(timezone.utc).isoformat()
    payload["service"] = service_metadata()
    return payload


@app.get("/api/policy")
def policy_state() -> dict[str, object]:
    payload = STATE_STORE.load()
    return {
        "rollout_channel": payload["rollout_channel"],
        "rollout_ring": payload["rollout_ring"],
        "maintenance_window_start": payload["maintenance_window_start"],
        "maintenance_window_end": payload["maintenance_window_end"],
        "trusted_http_sources": payload["trusted_http_sources"],
        "trusted_usb_roots": payload["trusted_usb_roots"],
        "retry_cooldown_minutes": payload["retry_cooldown_minutes"],
        "retention_keep_releases": payload["retention_keep_releases"],
        "failed_versions": payload["failed_versions"],
        "approved_updates": payload["approved_updates"],
    }


@app.get("/api/history")
def history() -> list[dict[str, object]]:
    return read_history(LAYOUT)


@app.get("/api/service")
def service() -> dict[str, object]:
    return service_metadata()


@app.get("/api/discovered")
def discovered() -> list[dict[str, object]]:
    return STATE_STORE.load().get("discovered_bundles", [])


@app.get("/api/discovered/latest")
def discovered_latest() -> dict[str, object] | None:
    selection = select_latest_compatible(STATE_STORE.load().get("discovered_bundles", []))
    if not selection:
        return None
    index, candidate = selection
    return {"index": index, "candidate": candidate}


@app.get("/api/audit/attempts")
def audit_attempts() -> list[dict[str, object]]:
    return summarize_attempts(read_history(LAYOUT))


@app.get("/api/audit/policy")
def audit_policy() -> dict[str, object]:
    return summarize_policy_events(read_history(LAYOUT))


@app.get("/api/audit/selection")
def audit_selection() -> dict[str, object]:
    return summarize_selection_events(read_history(LAYOUT))


@app.get("/api/audit/summary")
def audit_summary() -> dict[str, object]:
    history = read_history(LAYOUT)
    return {
        "attempts": summarize_attempts(history),
        "policy": summarize_policy_events(history),
        "selection": summarize_selection_events(history),
    }


@app.get("/api/audit/attempts/{attempt_id}")
def audit_attempt_detail(attempt_id: str) -> dict[str, object] | None:
    return find_attempt(summarize_attempts(read_history(LAYOUT)), attempt_id)
