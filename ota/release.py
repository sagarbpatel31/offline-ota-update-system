from __future__ import annotations

import json
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


def active_version(layout: ReleaseLayout) -> str | None:
    if not layout.active_link.exists() or not layout.active_link.is_symlink():
        return None
    return layout.active_link.resolve().name


def promote_release(layout: ReleaseLayout, version: str) -> None:
    target = layout.release_dir(version)
    if not target.exists():
        raise FileNotFoundError(f"release directory not found: {target}")

    layout.ensure()
    if layout.active_link.exists() or layout.active_link.is_symlink():
        layout.active_link.unlink()
    layout.active_link.symlink_to(target.resolve())


def append_history(layout: ReleaseLayout, event: dict[str, Any]) -> None:
    layout.ensure()
    with layout.history_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(event, sort_keys=True) + "\n")
