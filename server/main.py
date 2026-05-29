from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi import FastAPI

from demo_service.app import service_metadata
from ota.discovery import select_latest_compatible
from ota.release import ReleaseLayout, active_version, read_history, summarize_attempts, summarize_policy_events
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


@app.get("/api/audit/summary")
def audit_summary() -> dict[str, object]:
    history = read_history(LAYOUT)
    return {
        "attempts": summarize_attempts(history),
        "policy": summarize_policy_events(history),
    }
