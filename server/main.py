from datetime import datetime, timezone
import json
from pathlib import Path

from fastapi import FastAPI

from demo_service.app import service_metadata
from ota.discovery import select_latest_compatible
from ota.policy import source_backoff_active, source_quarantined
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


def source_health_metrics() -> dict[str, object]:
    payload = STATE_STORE.load()
    now = datetime.now(timezone.utc)
    source_health = payload.get("source_health", {})
    source_events = payload.get("source_events", [])
    sources: list[dict[str, object]] = []
    skip_reasons: dict[str, int] = {}
    event_counts = {"success": 0, "failure": 0, "skip": 0}
    for source, entry in source_health.items():
        source_entry = dict(entry)
        blocked_reason = None
        if source_quarantined(source_entry, now=now):
            blocked_reason = "source is quarantined"
        elif source_backoff_active(source_entry, now=now):
            blocked_reason = "source fetch backoff active"
        for reason, count in dict(source_entry.get("skip_reasons", {})).items():
            skip_reasons[reason] = skip_reasons.get(reason, 0) + int(count)
        source_entry["source"] = source
        source_entry["backoff_active"] = blocked_reason == "source fetch backoff active"
        source_entry["quarantined"] = blocked_reason == "source is quarantined"
        source_entry["blocked_reason"] = blocked_reason
        sources.append(source_entry)

    for event in source_events:
        event_type = str(event.get("event"))
        if event_type in event_counts:
            event_counts[event_type] += 1

    return {
        "sources": sources,
        "events": source_events[-50:],
        "summary": {
            "total_sources": len(sources),
            "quarantined_sources": sum(1 for source in sources if source["quarantined"]),
            "backoff_sources": sum(1 for source in sources if source["backoff_active"]),
            "skip_reasons": skip_reasons,
            "event_counts": event_counts,
        },
    }


def policy_metrics() -> dict[str, object]:
    discovered = STATE_STORE.load().get("discovered_bundles", [])
    selection_reasons: dict[str, int] = {}
    selectable = 0
    for candidate in discovered:
        if candidate.get("selectable") is True:
            selectable += 1
            continue
        reason = str(candidate.get("selection_reason") or "unknown")
        selection_reasons[reason] = selection_reasons.get(reason, 0) + 1
    return {
        "discovered_total": len(discovered),
        "selectable_total": selectable,
        "blocked_total": len(discovered) - selectable,
        "selection_reasons": selection_reasons,
    }


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
        "source_backoff_base_minutes": payload["source_backoff_base_minutes"],
        "source_quarantine_threshold": payload["source_quarantine_threshold"],
        "source_quarantine_minutes": payload["source_quarantine_minutes"],
        "source_event_history_limit": payload["source_event_history_limit"],
        "source_policies": payload["source_policies"],
        "failure_counts": payload["failure_counts"],
        "source_health": payload["source_health"],
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


@app.get("/api/metrics/policy")
def metrics_policy() -> dict[str, object]:
    return policy_metrics()


@app.get("/api/metrics/sources")
def metrics_sources() -> dict[str, object]:
    return source_health_metrics()
