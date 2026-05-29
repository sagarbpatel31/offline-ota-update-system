import json
import os
import shutil
import subprocess
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import cast
from urllib.error import URLError
from urllib.request import urlopen

import typer

from ota.bundle import BundleManifest, VerifiedBundle, load_signed_manifest, sha256_file
from ota.crypto import verify_manifest_signature
from ota.discovery import DiscoveryCandidate, discover_usb_candidates, download_http_bundle, select_latest_compatible
from ota.policy import adaptive_cooldown_minutes, cooldown_active, evaluate_manifest_policy, within_maintenance_window
from ota.release import (
    ReleaseLayout,
    active_version,
    append_history,
    copy_bundle_artifacts,
    find_attempt,
    previous_version,
    promote_release,
    prune_old_releases,
    read_history,
    rollback_release,
    stage_release,
    summarize_attempts,
    summarize_policy_events,
    summarize_selection_events,
)
from ota.state import DeviceStateStore, utc_now


app = typer.Typer(help="Offline OTA device agent")


class UpdateState(str, Enum):
    idle = "idle"
    discovering = "discovering"
    validating = "validating"
    staging = "staging"
    switching = "switching"
    verifying = "verifying"
    rollback = "rollback"
    failed = "failed"
    success = "success"


STATE_FILE = Path("artifacts/device-state.txt")
LAYOUT = ReleaseLayout(Path("artifacts/device"))
STATE_STORE = DeviceStateStore(Path("artifacts/device-state.json"))
DEFAULT_ACTIVATE_COMMAND = os.getenv("OFFLINE_OTA_ACTIVATE_COMMAND")
DEFAULT_USB_MOUNT_ROOTS = os.getenv("OFFLINE_OTA_USB_MOUNT_ROOTS", "/media,/mnt").split(",")
DEFAULT_HTTP_SOURCES = [value for value in os.getenv("OFFLINE_OTA_HTTP_SOURCES", "").split(",") if value]
DEFAULT_POLL_INTERVAL_SECONDS = int(os.getenv("OFFLINE_OTA_POLL_INTERVAL_SECONDS", "60"))
DEFAULT_ROLLOUT_RING = os.getenv("OFFLINE_OTA_ROLLOUT_RING", "general")
DEFAULT_MAINTENANCE_WINDOW_START = os.getenv("OFFLINE_OTA_MAINTENANCE_WINDOW_START")
DEFAULT_MAINTENANCE_WINDOW_END = os.getenv("OFFLINE_OTA_MAINTENANCE_WINDOW_END")
DEFAULT_TRUSTED_HTTP_SOURCES = [value for value in os.getenv("OFFLINE_OTA_TRUSTED_HTTP_SOURCES", "").split(",") if value]
DEFAULT_TRUSTED_USB_ROOTS = [value for value in os.getenv("OFFLINE_OTA_TRUSTED_USB_ROOTS", "").split(",") if value]
DEFAULT_RETRY_COOLDOWN_MINUTES = int(os.getenv("OFFLINE_OTA_RETRY_COOLDOWN_MINUTES", "30"))
DEFAULT_RETENTION_KEEP_RELEASES = int(os.getenv("OFFLINE_OTA_RETENTION_KEEP_RELEASES", "3"))


def read_state() -> str:
    payload = STATE_STORE.load()
    return payload["update_state"]


@app.command()
def status() -> None:
    typer.echo(f"device_state={read_state()}")


@app.command()
def set_state(state: UpdateState) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(state.value)
    STATE_STORE.update(update_state=state.value)
    typer.echo(f"device_state={state.value}")


def verify_artifacts(manifest: BundleManifest, bundle_dir: Path) -> None:
    for artifact in manifest.artifacts:
        artifact_path = bundle_dir / artifact.path
        if not artifact_path.exists():
            raise typer.BadParameter(f"artifact missing: {artifact_path}")
        actual_hash = sha256_file(artifact_path)
        if actual_hash != artifact.sha256:
            raise typer.BadParameter(
                f"hash mismatch for {artifact.path}: expected {artifact.sha256}, got {actual_hash}"
            )


def verify_bundle(bundle_path: Path, public_key: Path, bundle_dir: Path) -> VerifiedBundle:
    envelope = load_signed_manifest(bundle_path)
    verify_manifest_signature(envelope.manifest, envelope.signature, public_key)
    verify_artifacts(envelope.manifest, bundle_dir)
    return VerifiedBundle(envelope=envelope, manifest_path=bundle_path)


def record_event(layout: ReleaseLayout, event: str, **payload: str | None) -> None:
    append_history(
        layout,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": event,
            **payload,
        },
    )


def run_health_check(manifest: BundleManifest) -> tuple[bool, str | None]:
    if manifest.health_check.type != "http":
        return False, f"unsupported health check type: {manifest.health_check.type}"

    try:
        with urlopen(manifest.health_check.endpoint, timeout=manifest.health_check.timeout_seconds) as response:
            if 200 <= response.status < 300:
                return True, None
            return False, f"health check returned status {response.status}"
    except URLError as error:
        return False, str(error)


def run_activation_hook(command: str | None, root: Path) -> tuple[bool, str | None]:
    if not command:
        return True, None

    environment = os.environ.copy()
    environment["OFFLINE_OTA_RELEASE_ROOT"] = str((root / "active").resolve())
    completed = subprocess.run(
        command,
        shell=True,
        capture_output=True,
        text=True,
        env=environment,
    )
    if completed.returncode == 0:
        return True, None
    stderr = completed.stderr.strip()
    stdout = completed.stdout.strip()
    return False, stderr or stdout or f"activation hook failed with exit code {completed.returncode}"


def install_bundle_flow(
    bundle_path: Path,
    public_key: Path,
    bundle_dir: Path,
    root: Path,
    activate_command: str | None = DEFAULT_ACTIVATE_COMMAND,
) -> dict[str, str | None]:
    release_layout = ReleaseLayout(root)
    state_store = STATE_STORE
    device_state = state_store.load()
    state_store.update(
        update_state=UpdateState.validating.value,
        last_error=None,
        last_policy_error=None,
        last_checked_at=utc_now(),
    )

    verified_bundle = verify_bundle(bundle_path, public_key, bundle_dir)
    manifest = verified_bundle.envelope.manifest
    policy_result = evaluate_manifest_policy(
        manifest,
        device_model=device_state["device_model"],
        agent_version=device_state["agent_version"],
        active_version=device_state["active_version"],
    )

    if not policy_result.allowed:
        state_store.update(
            update_state=UpdateState.failed.value,
            candidate_version=manifest.version,
            last_policy_error=policy_result.reason,
            last_checked_at=utc_now(),
        )
        record_event(
            release_layout,
            "policy_rejected",
            version=manifest.version,
            error=policy_result.reason,
        )
        return state_store.load()

    state_store.update(candidate_version=manifest.version)
    record_event(release_layout, "verified", version=manifest.version)

    state_store.update(
        update_state=UpdateState.staging.value,
        previous_version=active_version(release_layout),
    )
    stage_release(release_layout, manifest.version)
    copy_bundle_artifacts(release_layout, manifest.version, bundle_dir)
    record_event(release_layout, "staged", version=manifest.version)

    state_store.update(update_state=UpdateState.switching.value)
    promote_release(release_layout, manifest.version)
    record_event(
        release_layout,
        "promote",
        version=manifest.version,
        previous_version=previous_version(release_layout),
    )

    activated, activation_error = run_activation_hook(activate_command, root)
    if not activated:
        state_store.update(
            update_state=UpdateState.failed.value,
            active_version=active_version(release_layout),
            candidate_version=manifest.version,
            previous_version=previous_version(release_layout),
            last_error=activation_error,
            last_checked_at=utc_now(),
        )
        record_event(
            release_layout,
            "activation_failed",
            version=manifest.version,
            error=activation_error,
        )
        rollback_target = previous_version(release_layout)
        if rollback_target:
            rolled_back_version = rollback_release(release_layout)
            run_activation_hook(activate_command, root)
            state_store.update(active_version=rolled_back_version, previous_version=previous_version(release_layout))
            record_event(
                release_layout,
                "rollback",
                version=manifest.version,
                restored_version=rolled_back_version,
                error=activation_error,
            )
        return state_store.load()

    state_store.update(
        update_state=UpdateState.verifying.value,
        active_version=manifest.version,
        last_checked_at=utc_now(),
    )
    healthy, error = run_health_check(manifest)
    if healthy:
        state_store.update(
            update_state=UpdateState.success.value,
            active_version=manifest.version,
            candidate_version=None,
            last_error=None,
            last_checked_at=utc_now(),
        )
        record_event(release_layout, "health_check_passed", version=manifest.version)
        failed_versions = state_store.load().get("failed_versions", {})
        failed_versions.pop(manifest.version, None)
        failure_counts = state_store.load().get("failure_counts", {})
        failure_counts.pop(manifest.version, None)
        state_store.update(failed_versions=failed_versions, failure_counts=failure_counts)
        return state_store.load()

    state_store.update(update_state=UpdateState.rollback.value, last_error=error, last_checked_at=utc_now())
    record_event(release_layout, "health_check_failed", version=manifest.version, error=error)

    rollback_target = previous_version(release_layout)
    if not rollback_target:
        state_store.update(
            update_state=UpdateState.failed.value,
            active_version=active_version(release_layout),
            candidate_version=manifest.version,
            previous_version=None,
            last_error=error,
            last_checked_at=utc_now(),
        )
        record_event(
            release_layout,
            "rollback_unavailable",
            version=manifest.version,
            error=error,
        )
        failed_versions = state_store.load().get("failed_versions", {})
        failed_versions[manifest.version] = utc_now()
        failure_counts = state_store.load().get("failure_counts", {})
        failure_counts[manifest.version] = int(failure_counts.get(manifest.version, 0)) + 1
        state_store.update(failed_versions=failed_versions, failure_counts=failure_counts)
        return state_store.load()

    rolled_back_version = rollback_release(release_layout)
    state_store.update(
        update_state=UpdateState.failed.value,
        active_version=rolled_back_version,
        candidate_version=manifest.version,
        previous_version=previous_version(release_layout),
        last_error=error,
        last_checked_at=utc_now(),
    )
    record_event(
        release_layout,
        "rollback",
        version=manifest.version,
        restored_version=rolled_back_version,
        error=error,
    )
    failed_versions = state_store.load().get("failed_versions", {})
    failed_versions[manifest.version] = utc_now()
    failure_counts = state_store.load().get("failure_counts", {})
    failure_counts[manifest.version] = int(failure_counts.get(manifest.version, 0)) + 1
    state_store.update(failed_versions=failed_versions, failure_counts=failure_counts)
    return state_store.load()


def policy_context() -> dict[str, str | None]:
    payload = STATE_STORE.load()
    return {
        "device_model": payload["device_model"],
        "agent_version": payload["agent_version"],
        "active_version": payload["active_version"],
    }


def approved_updates() -> set[str]:
    return set(STATE_STORE.load().get("approved_updates", []))


def approval_key(candidate: dict[str, object]) -> str:
    return f"{candidate['source']}|{candidate['version']}"


def source_health() -> dict[str, dict[str, object]]:
    return cast(dict[str, dict[str, object]], STATE_STORE.load().get("source_health", {}))


def record_source_success(source: str) -> None:
    health = source_health()
    current = health.get(source, {"score": 100, "successes": 0, "failures": 0, "last_error": None})
    current["score"] = min(100, int(current.get("score", 100)) + 5)
    current["successes"] = int(current.get("successes", 0)) + 1
    current["last_error"] = None
    current["last_seen_at"] = utc_now()
    health[source] = current
    STATE_STORE.update(source_health=health)


def record_source_failure(source: str, error: str) -> None:
    health = source_health()
    current = health.get(source, {"score": 100, "successes": 0, "failures": 0, "last_error": None})
    current["score"] = max(0, int(current.get("score", 100)) - 20)
    current["failures"] = int(current.get("failures", 0)) + 1
    current["last_error"] = error
    current["last_seen_at"] = utc_now()
    health[source] = current
    STATE_STORE.update(source_health=health, last_error=error)


def cooldown_minutes_for_state(state: dict[str, object], version: str) -> int:
    failure_count = int(cast(dict[str, int], state.get("failure_counts", {})).get(version, 0))
    return adaptive_cooldown_minutes(
        base_minutes=int(state.get("retry_cooldown_minutes", DEFAULT_RETRY_COOLDOWN_MINUTES)),
        failure_count=failure_count,
    )


def save_discovered_candidates(candidates: list[DiscoveryCandidate]) -> list[dict[str, object]]:
    payload = [candidate.as_dict() for candidate in candidates]
    STATE_STORE.update(discovered_bundles=payload, update_state=UpdateState.idle.value, last_checked_at=utc_now())
    return payload


def discovered_candidates() -> list[dict[str, object]]:
    return STATE_STORE.load().get("discovered_bundles", [])


def selected_candidate_payload() -> dict[str, object] | None:
    selection = select_latest_compatible(discovered_candidates())
    if not selection:
        return None
    index, candidate = selection
    return {"index": index, "candidate": candidate}


def discover_from_sources(
    usb_mount_roots: list[str] | None = None,
    http_sources: list[str] | None = None,
) -> list[dict[str, object]]:
    state = STATE_STORE.load()
    STATE_STORE.update(update_state=UpdateState.discovering.value, last_error=None, last_checked_at=utc_now())
    candidates: list[DiscoveryCandidate] = []

    for mount_root in DEFAULT_USB_MOUNT_ROOTS if usb_mount_roots is None else usb_mount_roots:
        root_path = Path(mount_root).expanduser()
        if root_path.exists():
            candidates.extend(
                discover_usb_candidates(
                    root_path,
                    policy_context=policy_context(),
                    rollout_channel=state["rollout_channel"],
                    rollout_ring=state["rollout_ring"],
                    approved_updates=approved_updates(),
                    maintenance_window_start=cast(str | None, state.get("maintenance_window_start")),
                    maintenance_window_end=cast(str | None, state.get("maintenance_window_end")),
                    trusted_sources=cast(list[str], state.get("trusted_usb_roots", [])),
                    failed_versions=cast(dict[str, str], state.get("failed_versions", {})),
                    failure_counts=cast(dict[str, int], state.get("failure_counts", {})),
                    retry_cooldown_minutes=int(state.get("retry_cooldown_minutes", DEFAULT_RETRY_COOLDOWN_MINUTES)),
                    source_health=source_health(),
                )
            )
            record_source_success(str(root_path))

    for http_source in DEFAULT_HTTP_SOURCES if http_sources is None else http_sources:
        try:
            candidates.append(
                download_http_bundle(
                    http_source,
                    cache_name=f"http-{len(candidates)}",
                    policy_context=policy_context(),
                    rollout_channel=state["rollout_channel"],
                    rollout_ring=state["rollout_ring"],
                    approved_updates=approved_updates(),
                    maintenance_window_start=cast(str | None, state.get("maintenance_window_start")),
                    maintenance_window_end=cast(str | None, state.get("maintenance_window_end")),
                    trusted_sources=cast(list[str], state.get("trusted_http_sources", [])),
                    failed_versions=cast(dict[str, str], state.get("failed_versions", {})),
                    failure_counts=cast(dict[str, int], state.get("failure_counts", {})),
                    retry_cooldown_minutes=int(state.get("retry_cooldown_minutes", DEFAULT_RETRY_COOLDOWN_MINUTES)),
                    source_health=source_health(),
                )
            )
            record_source_success(http_source)
        except Exception as error:
            record_source_failure(http_source, str(error))

    return save_discovered_candidates(candidates)


def refresh_cached_candidate_flags() -> list[dict[str, object]]:
    state = STATE_STORE.load()
    refreshed: list[dict[str, object]] = []
    approvals = approved_updates()
    allowed_channels = {"stable"} if state["rollout_channel"] == "stable" else {"stable", "canary"}
    allowed_rings = {"general"} if state["rollout_ring"] == "general" else {"general", state["rollout_ring"]}
    trusted_http_sources = cast(list[str], state.get("trusted_http_sources", []))
    trusted_usb_roots = cast(list[str], state.get("trusted_usb_roots", []))
    failed_versions = cast(dict[str, str], state.get("failed_versions", {}))
    failure_counts = cast(dict[str, int], state.get("failure_counts", {}))
    retry_cooldown_minutes = int(state.get("retry_cooldown_minutes", DEFAULT_RETRY_COOLDOWN_MINUTES))
    current_source_health = source_health()
    for candidate in discovered_candidates():
        refreshed_candidate = DiscoveryCandidate(
            source=str(candidate["source"]),
            source_type=str(candidate["source_type"]),
            bundle_path=Path(str(candidate["bundle_path"])),
            bundle_dir=Path(str(candidate["bundle_dir"])),
            public_key_path=Path(str(candidate["public_key_path"])) if candidate.get("public_key_path") else None,
            version=str(candidate["version"]),
            device_model=str(candidate["device_model"]),
            compatible=bool(candidate.get("compatible", True)),
            policy_reason=cast(str | None, candidate.get("policy_reason")),
            release_notes=cast(str | None, candidate.get("release_notes")),
            channel=str(candidate.get("channel", "stable")),
            ring=str(candidate.get("ring", "general")),
            priority=int(candidate.get("priority", 0)),
            approval_required=bool(candidate.get("approval_required", False)),
            approved=approval_key(candidate) in approvals or not bool(candidate.get("approval_required", False)),
            selectable=bool(candidate.get("compatible", True)),
            selection_reason=cast(str | None, candidate.get("policy_reason")),
            source_score=int(current_source_health.get(str(candidate["source"]), {}).get("score", candidate.get("source_score", 100))),
        )
        if refreshed_candidate.channel not in allowed_channels:
            refreshed_candidate.selectable = False
            refreshed_candidate.selection_reason = (
                f"channel {refreshed_candidate.channel} is not allowed for rollout channel {state['rollout_channel']}"
            )
        elif refreshed_candidate.ring not in allowed_rings:
            refreshed_candidate.selectable = False
            refreshed_candidate.selection_reason = (
                f"ring {refreshed_candidate.ring} is not allowed for rollout ring {state['rollout_ring']}"
            )
        elif refreshed_candidate.source_type == "http" and trusted_http_sources and not any(
            str(refreshed_candidate.source).startswith(prefix) for prefix in trusted_http_sources
        ):
            refreshed_candidate.selectable = False
            refreshed_candidate.selection_reason = "source is not trusted"
        elif refreshed_candidate.source_type == "usb" and trusted_usb_roots and not any(
            str(refreshed_candidate.source).startswith(prefix) for prefix in trusted_usb_roots
        ):
            refreshed_candidate.selectable = False
            refreshed_candidate.selection_reason = "source is not trusted"
        elif not within_maintenance_window(
            now=datetime.now(),
            window_start=cast(str | None, state.get("maintenance_window_start")),
            window_end=cast(str | None, state.get("maintenance_window_end")),
        ):
            refreshed_candidate.selectable = False
            refreshed_candidate.selection_reason = "outside maintenance window"
        elif cooldown_active(
            version=refreshed_candidate.version,
            failed_versions=failed_versions,
            cooldown_minutes=adaptive_cooldown_minutes(
                base_minutes=retry_cooldown_minutes,
                failure_count=int(failure_counts.get(refreshed_candidate.version, 0)),
            ),
            now=datetime.now(),
        ):
            refreshed_candidate.selectable = False
            refreshed_candidate.selection_reason = "retry cooldown active"
        elif refreshed_candidate.approval_required and not refreshed_candidate.approved:
            refreshed_candidate.selectable = False
            refreshed_candidate.selection_reason = "manual approval required"
        elif refreshed_candidate.compatible:
            refreshed_candidate.selectable = True
            refreshed_candidate.selection_reason = None
        refreshed.append(refreshed_candidate.as_dict())
    STATE_STORE.update(discovered_bundles=refreshed)
    return refreshed


@app.command()
def verify(
    bundle_path: Path = Path("manifests/signed-bundle.json"),
    public_key: Path = Path("keys/offline-ota-public.pem"),
    bundle_dir: Path = Path("artifacts/bundle"),
) -> None:
    verified_bundle = verify_bundle(bundle_path, public_key, bundle_dir)
    typer.echo(
        f"verified bundle version={verified_bundle.envelope.manifest.version} "
        f"device_model={verified_bundle.envelope.manifest.device_model}"
    )


@app.command()
def init_layout(root: Path = LAYOUT.root) -> None:
    layout = ReleaseLayout(root)
    layout.ensure()
    payload = STATE_STORE.load()
    payload["rollout_ring"] = payload.get("rollout_ring") or DEFAULT_ROLLOUT_RING
    payload["maintenance_window_start"] = payload.get("maintenance_window_start") or DEFAULT_MAINTENANCE_WINDOW_START
    payload["maintenance_window_end"] = payload.get("maintenance_window_end") or DEFAULT_MAINTENANCE_WINDOW_END
    payload["trusted_http_sources"] = payload.get("trusted_http_sources") or DEFAULT_TRUSTED_HTTP_SOURCES
    payload["trusted_usb_roots"] = payload.get("trusted_usb_roots") or DEFAULT_TRUSTED_USB_ROOTS
    payload["retry_cooldown_minutes"] = payload.get("retry_cooldown_minutes") or DEFAULT_RETRY_COOLDOWN_MINUTES
    payload["retention_keep_releases"] = payload.get("retention_keep_releases") or DEFAULT_RETENTION_KEEP_RELEASES
    STATE_STORE.save(payload)
    typer.echo(f"initialized release layout at {root}")


@app.command()
def stage(version: str, root: Path = LAYOUT.root) -> None:
    staged_dir = stage_release(ReleaseLayout(root), version)
    typer.echo(f"staged release directory at {staged_dir}")


@app.command()
def promote(version: str, root: Path = LAYOUT.root) -> None:
    release_layout = ReleaseLayout(root)
    previous_version = active_version(release_layout)
    promote_release(release_layout, version)
    STATE_STORE.update(active_version=version, previous_version=previous_version)
    record_event(release_layout, "promote", version=version, previous_version=previous_version)
    typer.echo(f"promoted active release to {version}")


@app.command()
def install(
    bundle_path: Path = Path("manifests/signed-bundle.json"),
    public_key: Path = Path("keys/offline-ota-public.pem"),
    bundle_dir: Path = Path("artifacts/bundle"),
    root: Path = LAYOUT.root,
    activate_command: str | None = DEFAULT_ACTIVATE_COMMAND,
) -> None:
    payload = install_bundle_flow(bundle_path, public_key, bundle_dir, root, activate_command)
    typer.echo(json.dumps(payload, indent=2))


@app.command("discover-usb")
def discover_usb(
    mount_root: Path = Path("/media"),
) -> None:
    payload = discover_from_sources(usb_mount_roots=[str(mount_root)], http_sources=[])
    typer.echo(json.dumps(payload, indent=2))


@app.command("discover-http")
def discover_http(
    base_url: str,
) -> None:
    payload = discover_from_sources(usb_mount_roots=[], http_sources=[base_url])
    typer.echo(json.dumps(payload, indent=2))


@app.command("list-discovered")
def list_discovered() -> None:
    typer.echo(json.dumps(discovered_candidates(), indent=2))


@app.command("select-latest")
def select_latest() -> None:
    payload = selected_candidate_payload()
    if payload:
        record_event(
            LAYOUT,
            "selection_made",
            version=str(payload["candidate"]["version"]),
            source=str(payload["candidate"]["source"]),
            source_type=str(payload["candidate"]["source_type"]),
        )
    typer.echo(json.dumps(payload, indent=2))


@app.command("set-rollout-channel")
def set_rollout_channel(channel: str) -> None:
    if channel not in {"stable", "canary"}:
        raise typer.BadParameter("rollout channel must be 'stable' or 'canary'")
    STATE_STORE.update(rollout_channel=channel)
    record_event(LAYOUT, "rollout_channel_changed", version=channel)
    typer.echo(json.dumps({"rollout_channel": channel, "discovered": refresh_cached_candidate_flags()}, indent=2))


@app.command("set-rollout-ring")
def set_rollout_ring(ring: str) -> None:
    if ring not in {"general", "canary-a", "canary-b"}:
        raise typer.BadParameter("rollout ring must be one of: general, canary-a, canary-b")
    STATE_STORE.update(rollout_ring=ring)
    record_event(LAYOUT, "rollout_ring_changed", version=ring)
    typer.echo(json.dumps({"rollout_ring": ring, "discovered": refresh_cached_candidate_flags()}, indent=2))


@app.command("set-maintenance-window")
def set_maintenance_window(start: str, end: str) -> None:
    STATE_STORE.update(maintenance_window_start=start, maintenance_window_end=end)
    record_event(LAYOUT, "maintenance_window_changed", version=f"{start}-{end}")
    typer.echo(
        json.dumps(
            {
                "maintenance_window_start": start,
                "maintenance_window_end": end,
                "discovered": refresh_cached_candidate_flags(),
            },
            indent=2,
        )
    )


@app.command("set-trusted-http-sources")
def set_trusted_http_sources(sources: list[str]) -> None:
    STATE_STORE.update(trusted_http_sources=sources)
    record_event(LAYOUT, "trusted_http_sources_changed", version=",".join(sources) or "none")
    typer.echo(json.dumps({"trusted_http_sources": sources, "discovered": refresh_cached_candidate_flags()}, indent=2))


@app.command("set-trusted-usb-roots")
def set_trusted_usb_roots(roots: list[str]) -> None:
    STATE_STORE.update(trusted_usb_roots=roots)
    record_event(LAYOUT, "trusted_usb_roots_changed", version=",".join(roots) or "none")
    typer.echo(json.dumps({"trusted_usb_roots": roots, "discovered": refresh_cached_candidate_flags()}, indent=2))


@app.command("set-retry-cooldown")
def set_retry_cooldown(minutes: int) -> None:
    STATE_STORE.update(retry_cooldown_minutes=minutes)
    record_event(LAYOUT, "retry_cooldown_changed", version=str(minutes))
    typer.echo(json.dumps({"retry_cooldown_minutes": minutes, "discovered": refresh_cached_candidate_flags()}, indent=2))


@app.command("set-retention")
def set_retention(keep_releases: int) -> None:
    STATE_STORE.update(retention_keep_releases=keep_releases)
    record_event(LAYOUT, "retention_changed", version=str(keep_releases))
    typer.echo(json.dumps({"retention_keep_releases": keep_releases}, indent=2))


@app.command("cleanup")
def cleanup(root: Path = LAYOUT.root) -> None:
    state = STATE_STORE.load()
    removed_releases = prune_old_releases(ReleaseLayout(root), int(state.get("retention_keep_releases", DEFAULT_RETENTION_KEEP_RELEASES)))
    discovery_root = Path("artifacts/discovery")
    removed_discovery: list[str] = []
    if discovery_root.exists():
        candidates = {str(Path(candidate["bundle_path"]).resolve().parent) for candidate in discovered_candidates()}
        for cache_dir in discovery_root.iterdir():
            if cache_dir.is_dir() and str(cache_dir.resolve()) not in candidates:
                shutil.rmtree(cache_dir, ignore_errors=True)
                removed_discovery.append(cache_dir.name)
    record_event(LAYOUT, "cleanup_ran", version="cleanup")
    typer.echo(json.dumps({"removed_releases": removed_releases, "removed_discovery": removed_discovery}, indent=2))


@app.command("list-approvals")
def list_approvals() -> None:
    typer.echo(json.dumps(sorted(approved_updates()), indent=2))


@app.command("approve-discovered")
def approve_discovered(index: int) -> None:
    candidates = discovered_candidates()
    if index < 0 or index >= len(candidates):
        raise typer.BadParameter(f"discovery index out of range: {index}")
    approvals = approved_updates()
    approvals.add(approval_key(candidates[index]))
    STATE_STORE.update(approved_updates=sorted(approvals))
    record_event(LAYOUT, "approval_granted", version=str(candidates[index]["version"]), source=str(candidates[index]["source"]))
    refresh = refresh_cached_candidate_flags()
    typer.echo(json.dumps({"approved": approval_key(candidates[index]), "discovered": refresh}, indent=2))


@app.command("revoke-approval")
def revoke_approval(index: int) -> None:
    candidates = discovered_candidates()
    if index < 0 or index >= len(candidates):
        raise typer.BadParameter(f"discovery index out of range: {index}")
    approvals = approved_updates()
    approvals.discard(approval_key(candidates[index]))
    STATE_STORE.update(approved_updates=sorted(approvals))
    record_event(LAYOUT, "approval_revoked", version=str(candidates[index]["version"]), source=str(candidates[index]["source"]))
    refresh = refresh_cached_candidate_flags()
    typer.echo(json.dumps({"revoked": approval_key(candidates[index]), "discovered": refresh}, indent=2))


@app.command("install-discovered")
def install_discovered(
    index: int = 0,
    root: Path = LAYOUT.root,
    activate_command: str | None = DEFAULT_ACTIVATE_COMMAND,
) -> None:
    candidates = discovered_candidates()
    if not candidates:
        raise typer.BadParameter("no discovered bundles available")
    if index < 0 or index >= len(candidates):
        raise typer.BadParameter(f"discovery index out of range: {index}")

    candidate = candidates[index]
    if candidate.get("selectable") is not True:
        raise typer.BadParameter(f"discovered bundle is not selectable: {candidate.get('selection_reason')}")
    public_key = candidate.get("public_key_path")
    if not public_key:
        raise typer.BadParameter("discovered bundle is missing a public key path")

    payload = install_bundle_flow(
        bundle_path=Path(candidate["bundle_path"]),
        public_key=Path(public_key),
        bundle_dir=Path(candidate["bundle_dir"]),
        root=root,
        activate_command=activate_command,
    )
    typer.echo(json.dumps(payload, indent=2))


@app.command("install-latest")
def install_latest(
    root: Path = LAYOUT.root,
    activate_command: str | None = DEFAULT_ACTIVATE_COMMAND,
) -> None:
    payload = selected_candidate_payload()
    if not payload:
        raise typer.BadParameter("no compatible discovered bundles available")
    candidate = payload["candidate"]
    record_event(
        LAYOUT,
        "selection_made",
        version=str(candidate["version"]),
        source=str(candidate["source"]),
        source_type=str(candidate["source_type"]),
    )
    public_key = candidate.get("public_key_path")
    if not public_key:
        raise typer.BadParameter("selected bundle is missing a public key path")
    install_payload = install_bundle_flow(
        bundle_path=Path(candidate["bundle_path"]),
        public_key=Path(public_key),
        bundle_dir=Path(candidate["bundle_dir"]),
        root=root,
        activate_command=activate_command,
    )
    typer.echo(json.dumps({"selected_index": payload["index"], "result": install_payload}, indent=2))


@app.command("poll-once")
def poll_once(
    usb_mount_roots: list[str] | None = None,
    http_sources: list[str] | None = None,
    root: Path = LAYOUT.root,
    activate_command: str | None = DEFAULT_ACTIVATE_COMMAND,
) -> None:
    discovered = discover_from_sources(usb_mount_roots=usb_mount_roots, http_sources=http_sources)
    selection = select_latest_compatible(discovered)
    if not selection:
        typer.echo(json.dumps({"discovered": discovered, "selected": None}, indent=2))
        return

    index, candidate = selection
    record_event(
        LAYOUT,
        "selection_made",
        version=str(candidate["version"]),
        source=str(candidate["source"]),
        source_type=str(candidate["source_type"]),
    )
    public_key = candidate.get("public_key_path")
    if not public_key:
        raise typer.BadParameter("selected bundle is missing a public key path")

    result = install_bundle_flow(
        bundle_path=Path(candidate["bundle_path"]),
        public_key=Path(public_key),
        bundle_dir=Path(candidate["bundle_dir"]),
        root=root,
        activate_command=activate_command,
    )
    typer.echo(json.dumps({"discovered": discovered, "selected_index": index, "result": result}, indent=2))


@app.command("poll-loop")
def poll_loop(
    interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
    usb_mount_roots: list[str] | None = None,
    http_sources: list[str] | None = None,
    root: Path = LAYOUT.root,
    activate_command: str | None = DEFAULT_ACTIVATE_COMMAND,
) -> None:
    while True:
        try:
            poll_once(
                usb_mount_roots=usb_mount_roots,
                http_sources=http_sources,
                root=root,
                activate_command=activate_command,
            )
        except KeyboardInterrupt:
            raise
        except Exception as error:
            STATE_STORE.update(update_state=UpdateState.failed.value, last_error=str(error), last_checked_at=utc_now())
            typer.echo(json.dumps({"error": str(error)}, indent=2))
        time.sleep(interval_seconds)


@app.command()
def rollback(root: Path = LAYOUT.root) -> None:
    release_layout = ReleaseLayout(root)
    restored_version = rollback_release(release_layout)
    STATE_STORE.update(
        update_state=UpdateState.failed.value,
        active_version=restored_version,
        candidate_version=None,
        previous_version=previous_version(release_layout),
    )
    record_event(release_layout, "manual_rollback", restored_version=restored_version)
    typer.echo(f"rolled back to {restored_version}")


@app.command()
def device_status() -> None:
    typer.echo(json.dumps(STATE_STORE.load(), indent=2))


@app.command()
def layout(root: Path = LAYOUT.root) -> None:
    release_layout = ReleaseLayout(root)
    payload = {
        "root": str(release_layout.root),
        "releases_dir": str(release_layout.releases_dir),
        "active_link": str(release_layout.active_link),
        "history_file": str(release_layout.history_file),
        "active_version": active_version(release_layout),
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command("audit-summary")
def audit_summary(root: Path = LAYOUT.root) -> None:
    release_layout = ReleaseLayout(root)
    history = read_history(release_layout)
    payload = {
        "attempts": summarize_attempts(history),
        "policy": summarize_policy_events(history),
        "selection": summarize_selection_events(history),
    }
    typer.echo(json.dumps(payload, indent=2))


@app.command("audit-attempt")
def audit_attempt(attempt_id: str, root: Path = LAYOUT.root) -> None:
    release_layout = ReleaseLayout(root)
    attempt = find_attempt(summarize_attempts(read_history(release_layout)), attempt_id)
    typer.echo(json.dumps(attempt, indent=2))


if __name__ == "__main__":
    app()
