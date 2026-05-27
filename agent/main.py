from enum import Enum
from pathlib import Path

import typer


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


if __name__ == "__main__":
    app()

