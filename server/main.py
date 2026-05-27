from datetime import datetime, timezone

from fastapi import FastAPI


app = FastAPI(title="Offline OTA Dashboard", version="0.1.0")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/api/status")
def status() -> dict[str, object]:
    return {
        "device_id": "demo-device-001",
        "active_version": "1.0.0",
        "candidate_version": None,
        "update_state": "idle",
        "last_checked_at": datetime.now(timezone.utc).isoformat(),
    }

