from __future__ import annotations

import shutil
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
