import json
import os
import subprocess
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

import typer

from ota.bundle import BundleManifest, VerifiedBundle, load_signed_manifest, sha256_file
from ota.crypto import verify_manifest_signature
from ota.discovery import DiscoveryCandidate, discover_usb_candidates, download_http_bundle, select_latest_compatible
from ota.policy import evaluate_manifest_policy
from ota.release import (
    ReleaseLayout,
    active_version,
    append_history,
    copy_bundle_artifacts,
    previous_version,
    promote_release,
    rollback_release,
    stage_release,
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
    return state_store.load()


def policy_context() -> dict[str, str | None]:
    payload = STATE_STORE.load()
    return {
        "device_model": payload["device_model"],
        "agent_version": payload["agent_version"],
        "active_version": payload["active_version"],
    }


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
    STATE_STORE.save(STATE_STORE.load())
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
    STATE_STORE.update(update_state=UpdateState.discovering.value, last_error=None, last_checked_at=utc_now())
    candidates = discover_usb_candidates(mount_root, policy_context=policy_context())
    payload = save_discovered_candidates(candidates)
    typer.echo(json.dumps(payload, indent=2))


@app.command("discover-http")
def discover_http(
    base_url: str,
) -> None:
    STATE_STORE.update(update_state=UpdateState.discovering.value, last_error=None, last_checked_at=utc_now())
    candidate = download_http_bundle(base_url, policy_context=policy_context())
    payload = save_discovered_candidates([candidate])
    typer.echo(json.dumps(payload, indent=2))


@app.command("list-discovered")
def list_discovered() -> None:
    typer.echo(json.dumps(discovered_candidates(), indent=2))


@app.command("select-latest")
def select_latest() -> None:
    payload = selected_candidate_payload()
    typer.echo(json.dumps(payload, indent=2))


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
    compatible = candidate.get("compatible")
    if compatible is False:
        raise typer.BadParameter(f"discovered bundle is incompatible: {candidate.get('policy_reason')}")
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


if __name__ == "__main__":
    app()
