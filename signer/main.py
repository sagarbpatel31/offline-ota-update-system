import json
from pathlib import Path

import typer


app = typer.Typer(help="Bundle manifest generator")


@app.command()
def sample_manifest(output: Path = Path("manifests/generated.manifest.json")) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    manifest = {
        "version": "1.1.0",
        "device_model": "raspberry-pi-4",
        "minimum_agent_version": "0.1.0",
        "artifacts": [
            {
                "name": "demo-service.tar.gz",
                "sha256": "replace-with-real-sha256",
                "size_bytes": 0,
            }
        ],
        "health_check": {
            "type": "http",
            "endpoint": "http://127.0.0.1:8080/health",
            "timeout_seconds": 30,
        },
    }
    output.write_text(json.dumps(manifest, indent=2) + "\n")
    typer.echo(f"wrote {output}")


if __name__ == "__main__":
    app()

