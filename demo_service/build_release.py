from __future__ import annotations

import json
from pathlib import Path

import typer


app = typer.Typer(help="Build demo service release artifacts")


@app.command()
def build(
    version: str,
    output_dir: Path = Path("artifacts/bundle"),
    message: str = "Demo service release",
) -> None:
    service_dir = output_dir / "service"
    service_dir.mkdir(parents=True, exist_ok=True)

    metadata = {
        "service_name": "offline-ota-demo-service",
        "version": version,
        "message": message,
        "status": "ok",
    }

    (service_dir / "version.json").write_text(json.dumps(metadata, indent=2) + "\n")
    (service_dir / "README.txt").write_text(
        f"Offline OTA demo release {version}\n"
        "This directory is copied into the active release during install.\n"
    )
    typer.echo(f"wrote demo release to {output_dir}")


if __name__ == "__main__":
    app()

