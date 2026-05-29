from __future__ import annotations

import shutil
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass
class ReleaseLayout:
    root: Path

    @property
    def releases_dir(self) -> Path:
        return self.root / "releases"

    @property
    def active_link(self) -> Path:
        return self.root / "active"

    @property
    def history_file(self) -> Path:
        return self.root / "update-history.jsonl"

    @property
    def previous_version_file(self) -> Path:
        return self.root / "previous-version.txt"

    def ensure(self) -> None:
        self.releases_dir.mkdir(parents=True, exist_ok=True)
        self.history_file.parent.mkdir(parents=True, exist_ok=True)

    def release_dir(self, version: str) -> Path:
        return self.releases_dir / version


def stage_release(layout: ReleaseLayout, version: str) -> Path:
    layout.ensure()
    staged_dir = layout.release_dir(version)
    staged_dir.mkdir(parents=True, exist_ok=True)
    return staged_dir


def clear_release_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def copy_bundle_artifacts(layout: ReleaseLayout, version: str, bundle_dir: Path) -> Path:
    target_dir = layout.release_dir(version)
    clear_release_dir(target_dir)
    for source_path in sorted(path for path in bundle_dir.rglob("*") if path.is_file()):
        relative_path = source_path.relative_to(bundle_dir)
        destination = target_dir / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source_path, destination)
    return target_dir


def active_version(layout: ReleaseLayout) -> str | None:
    if not layout.active_link.exists() or not layout.active_link.is_symlink():
        return None
    return layout.active_link.resolve().name


def promote_release(layout: ReleaseLayout, version: str, record_previous: bool = True) -> None:
    target = layout.release_dir(version)
    if not target.exists():
        raise FileNotFoundError(f"release directory not found: {target}")

    layout.ensure()
    current_active = active_version(layout)
    if layout.active_link.exists() or layout.active_link.is_symlink():
        layout.active_link.unlink()
    layout.active_link.symlink_to(target.resolve())
    if record_previous and current_active:
        layout.previous_version_file.write_text(current_active + "\n")


def previous_version(layout: ReleaseLayout) -> str | None:
    if not layout.previous_version_file.exists():
        return None
    value = layout.previous_version_file.read_text().strip()
    return value or None


def rollback_release(layout: ReleaseLayout) -> str:
    target_version = previous_version(layout)
    if not target_version:
        raise FileNotFoundError("previous version not recorded")
    promote_release(layout, target_version, record_previous=False)
    layout.previous_version_file.write_text(target_version + "\n")
    return target_version


def append_history(layout: ReleaseLayout, event: dict[str, Any]) -> None:
    layout.ensure()
    with layout.history_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")


def read_history(layout: ReleaseLayout) -> list[dict[str, Any]]:
    if not layout.history_file.exists():
        return []
    return [json.loads(line) for line in layout.history_file.read_text().splitlines() if line.strip()]


def summarize_attempts(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    terminal_events = {
        "health_check_passed": "success",
        "rollback": "rolled_back",
        "rollback_unavailable": "failed_without_rollback",
        "policy_rejected": "policy_rejected",
        "activation_failed": "activation_failed",
    }
    attempts: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None

    for event in history:
        event_name = event.get("event")
        version = event.get("version")
        timestamp = event.get("timestamp")

        if event_name in {"verified", "policy_rejected"}:
            current = {
                "attempt_id": make_attempt_id(str(timestamp), str(version)),
                "version": version,
                "started_at": timestamp,
                "status": terminal_events.get(event_name, "in_progress"),
                "events": [event_name],
                "timeline": [event],
                "error": event.get("error"),
                "restored_version": None,
            }
            if event_name in terminal_events:
                current["finished_at"] = timestamp
            attempts.append(current)
        elif current and current.get("version") == version:
            current["events"].append(event_name)
            current["timeline"].append(event)
            if event.get("error"):
                current["error"] = event.get("error")
            if event.get("restored_version"):
                current["restored_version"] = event.get("restored_version")
            if event_name in terminal_events:
                current["status"] = terminal_events[event_name]
                current["finished_at"] = timestamp

    return attempts


def make_attempt_id(timestamp: str, version: str) -> str:
    raw = f"{timestamp}-{version}"
    return re.sub(r"[^A-Za-z0-9]+", "-", raw).strip("-").lower()


def find_attempt(attempts: list[dict[str, Any]], attempt_id: str) -> dict[str, Any] | None:
    for attempt in attempts:
        if attempt.get("attempt_id") == attempt_id:
            return attempt
    return None


def summarize_selection_events(history: list[dict[str, Any]]) -> dict[str, Any]:
    selections = [event for event in history if event.get("event") == "selection_made"]
    by_source_type: dict[str, int] = {}
    for event in selections:
        source_type = event.get("source_type") or "unknown"
        by_source_type[source_type] = by_source_type.get(source_type, 0) + 1
    return {
        "count": len(selections),
        "by_source_type": by_source_type,
        "latest": selections[-1] if selections else None,
    }


def summarize_policy_events(history: list[dict[str, Any]]) -> dict[str, Any]:
    policy_rejections = [event for event in history if event.get("event") == "policy_rejected"]
    by_reason: dict[str, int] = {}
    for event in policy_rejections:
        reason = event.get("error") or "unknown"
        by_reason[reason] = by_reason.get(reason, 0) + 1

    return {
        "count": len(policy_rejections),
        "by_reason": by_reason,
        "latest": policy_rejections[-1] if policy_rejections else None,
    }
