from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi import FastAPI

from ota.release import ReleaseLayout, active_version
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
    return payload


@app.get("/api/history")
def history() -> list[dict[str, object]]:
    if not LAYOUT.history_file.exists():
        return []
    return [json.loads(line) for line in LAYOUT.history_file.read_text().splitlines() if line.strip()]
