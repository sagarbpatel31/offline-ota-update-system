from pathlib import Path

import typer

from ota.bundle import ArtifactManifest, BundleManifest, HealthCheck, SignedManifestEnvelope, sha256_file
from ota.crypto import generate_keypair, sign_manifest


app = typer.Typer(help="Bundle manifest generator")


@app.command()
def generate_keys(
    private_key: Path = Path("keys/offline-ota-private.pem"),
    public_key: Path = Path("keys/offline-ota-public.pem"),
) -> None:
    generate_keypair(private_key, public_key)
    typer.echo(f"wrote private key to {private_key}")
    typer.echo(f"wrote public key to {public_key}")


@app.command()
def sample_manifest(output: Path = Path("manifests/generated.manifest.json")) -> None:
    manifest = BundleManifest(
        version="1.1.0",
        device_model="raspberry-pi-4",
        minimum_agent_version="0.1.0",
        artifacts=[
            ArtifactManifest(
                name="demo-service.tar.gz",
                path="artifacts/demo-service.tar.gz",
                sha256="replace-with-real-sha256",
                size_bytes=0,
            )
        ],
        health_check=HealthCheck(
            type="http",
            endpoint="http://127.0.0.1:8080/health",
            timeout_seconds=30,
        ),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(manifest.model_dump_json(indent=2) + "\n")
    typer.echo(f"wrote {output}")


@app.command()
def build_manifest(
    artifacts_dir: Path,
    version: str,
    device_model: str = "raspberry-pi-4",
    minimum_agent_version: str = "0.1.0",
    health_endpoint: str = "http://127.0.0.1:8080/health",
    output: Path = Path("manifests/bundle.manifest.json"),
) -> None:
    if not artifacts_dir.exists():
        raise typer.BadParameter(f"artifacts directory not found: {artifacts_dir}")

    artifacts: list[ArtifactManifest] = []
    for artifact_path in sorted(path for path in artifacts_dir.rglob("*") if path.is_file()):
        artifacts.append(
            ArtifactManifest(
                name=artifact_path.name,
                path=str(artifact_path.relative_to(artifacts_dir)),
                sha256=sha256_file(artifact_path),
                size_bytes=artifact_path.stat().st_size,
            )
        )

    manifest = BundleManifest(
        version=version,
        device_model=device_model,
        minimum_agent_version=minimum_agent_version,
        artifacts=artifacts,
        health_check=HealthCheck(
            type="http",
            endpoint=health_endpoint,
            timeout_seconds=30,
        ),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(manifest.model_dump_json(indent=2) + "\n")
    typer.echo(f"wrote {output}")


@app.command()
def sign_bundle(
    manifest_path: Path,
    private_key: Path = Path("keys/offline-ota-private.pem"),
    output: Path = Path("manifests/signed-bundle.json"),
) -> None:
    manifest = BundleManifest.model_validate_json(manifest_path.read_text())
    envelope = SignedManifestEnvelope(
        manifest=manifest,
        signature=sign_manifest(manifest, private_key),
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(envelope.model_dump_json(indent=2) + "\n")
    typer.echo(f"wrote {output}")


if __name__ == "__main__":
    app()
