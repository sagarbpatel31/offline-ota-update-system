from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI


app = FastAPI(title="Offline OTA Demo Service", version="0.1.0")


def release_root() -> Path:
    return Path(os.getenv("OFFLINE_OTA_RELEASE_ROOT", "artifacts/device/active"))


def service_metadata() -> dict[str, object]:
    metadata_path = release_root() / "service" / "version.json"
    if not metadata_path.exists():
        return {
            "service_name": "offline-ota-demo-service",
            "version": None,
            "message": "no active release",
            "status": "degraded",
        }
    return json.loads(metadata_path.read_text())


@app.get("/health")
def health() -> dict[str, object]:
    metadata = service_metadata()
    return {
        "status": "ok" if metadata.get("version") else "degraded",
        "service": metadata,
    }


@app.get("/api/service")
def service_status() -> dict[str, object]:
    return service_metadata()
