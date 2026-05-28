from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class DeviceStateStore:
    path: Path

    def default_state(self) -> dict[str, Any]:
        return {
            "device_id": "rpi-demo-001",
            "device_model": "raspberry-pi-4",
            "agent_version": "0.1.0",
            "update_state": "idle",
            "active_version": None,
            "candidate_version": None,
            "previous_version": None,
            "discovered_bundles": [],
            "last_policy_error": None,
            "last_error": None,
            "last_checked_at": None,
            "last_updated_at": None,
        }

    def load(self) -> dict[str, Any]:
        if not self.path.exists():
            return self.default_state()
        return {**self.default_state(), **json.loads(self.path.read_text())}

    def save(self, payload: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        merged = {**self.default_state(), **payload, "last_updated_at": utc_now()}
        self.path.write_text(json.dumps(merged, indent=2) + "\n")

    def update(self, **changes: Any) -> dict[str, Any]:
        payload = self.load()
        payload.update(changes)
        self.save(payload)
        return payload
