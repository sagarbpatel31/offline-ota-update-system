import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

import typer

from ota.bundle import BundleManifest, VerifiedBundle, load_signed_manifest, sha256_file
from ota.crypto import verify_manifest_signature
from ota.release import ReleaseLayout, active_version, append_history, promote_release, stage_release


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


def read_state() -> str:
    if not STATE_FILE.exists():
        return UpdateState.idle.value
    return STATE_FILE.read_text().strip() or UpdateState.idle.value


@app.command()
def status() -> None:
    typer.echo(f"device_state={read_state()}")


@app.command()
def set_state(state: UpdateState) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(state.value)
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
    append_history(
        release_layout,
        {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "promote",
            "version": version,
            "previous_version": previous_version,
        },
    )
    typer.echo(f"promoted active release to {version}")


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
