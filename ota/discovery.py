from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urljoin
from urllib.request import urlopen

from ota.bundle import SignedManifestEnvelope, load_signed_manifest
from ota.policy import (
    PolicyResult,
    cooldown_active,
    evaluate_manifest_policy,
    parse_version,
    source_is_trusted,
    within_maintenance_window,
)


@dataclass
class DiscoveryCandidate:
    source: str
    source_type: str
    bundle_path: Path
    bundle_dir: Path
    public_key_path: Path | None
    version: str
    device_model: str
    compatible: bool = True
    policy_reason: str | None = None
    release_notes: str | None = None
    channel: str = "stable"
    ring: str = "general"
    priority: int = 0
    approval_required: bool = False
    approved: bool = True
    selectable: bool = True
    selection_reason: str | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "source": self.source,
            "source_type": self.source_type,
            "bundle_path": str(self.bundle_path),
            "bundle_dir": str(self.bundle_dir),
            "public_key_path": str(self.public_key_path) if self.public_key_path else None,
            "version": self.version,
            "device_model": self.device_model,
            "compatible": self.compatible,
            "policy_reason": self.policy_reason,
            "release_notes": self.release_notes,
            "channel": self.channel,
            "ring": self.ring,
            "priority": self.priority,
            "approval_required": self.approval_required,
            "approved": self.approved,
            "selectable": self.selectable,
            "selection_reason": self.selection_reason,
        }


def discovery_root() -> Path:
    return Path("artifacts/discovery")


def discovery_cache_dir(name: str) -> Path:
    return discovery_root() / name


def parse_bundle_index(path: Path) -> dict[str, object]:
    if not path.exists():
        return {}
    return json.loads(path.read_text())


def load_candidate(
    bundle_path: Path,
    source: str,
    source_type: str,
    public_key_path: Path | None = None,
    *,
    policy_result: PolicyResult | None = None,
    rollout_channel: str = "stable",
    rollout_ring: str = "general",
    approved_updates: set[str] | None = None,
    maintenance_window_start: str | None = None,
    maintenance_window_end: str | None = None,
    trusted_sources: list[str] | None = None,
    failed_versions: dict[str, str] | None = None,
    retry_cooldown_minutes: int = 30,
) -> DiscoveryCandidate:
    envelope = load_signed_manifest(bundle_path)
    manifest = envelope.manifest
    bundle_index = parse_bundle_index(bundle_path.parent / "bundle-index.json")
    channel = str(bundle_index.get("channel", "stable"))
    ring = str(bundle_index.get("ring", "general"))
    priority = int(bundle_index.get("priority", 0))
    approval_required = bool(bundle_index.get("requires_approval", False))
    approval_key = f"{source}|{manifest.version}"
    approved = (not approval_required) or (approved_updates is not None and approval_key in approved_updates)
    allowed_channels = {"stable"} if rollout_channel == "stable" else {"stable", "canary"}
    allowed_rings = {"general"} if rollout_ring == "general" else {"general", rollout_ring}
    selection_reason = None
    selectable = True
    if channel not in allowed_channels:
        selectable = False
        selection_reason = f"channel {channel} is not allowed for rollout channel {rollout_channel}"
    elif ring not in allowed_rings:
        selectable = False
        selection_reason = f"ring {ring} is not allowed for rollout ring {rollout_ring}"
    elif not source_is_trusted(source, trusted_sources=trusted_sources or []):
        selectable = False
        selection_reason = "source is not trusted"
    elif not within_maintenance_window(
        now=datetime.now(),
        window_start=maintenance_window_start,
        window_end=maintenance_window_end,
    ):
        selectable = False
        selection_reason = "outside maintenance window"
    elif cooldown_active(
        version=manifest.version,
        failed_versions=failed_versions or {},
        cooldown_minutes=retry_cooldown_minutes,
        now=datetime.now(),
    ):
        selectable = False
        selection_reason = "retry cooldown active"
    elif policy_result and not policy_result.allowed:
        selectable = False
        selection_reason = policy_result.reason
    elif approval_required and not approved:
        selectable = False
        selection_reason = "manual approval required"
    return DiscoveryCandidate(
        source=source,
        source_type=source_type,
        bundle_path=bundle_path,
        bundle_dir=bundle_path.parent / "bundle",
        public_key_path=public_key_path,
        version=manifest.version,
        device_model=manifest.device_model,
        compatible=policy_result.allowed if policy_result else True,
        policy_reason=policy_result.reason if policy_result else None,
        release_notes=bundle_index.get("release_notes"),
        channel=channel,
        ring=ring,
        priority=priority,
        approval_required=approval_required,
        approved=approved,
        selectable=selectable,
        selection_reason=selection_reason,
    )


def discover_usb_candidates(
    mount_root: Path,
    *,
    policy_context: dict[str, str | None] | None = None,
    rollout_channel: str = "stable",
    rollout_ring: str = "general",
    approved_updates: set[str] | None = None,
    maintenance_window_start: str | None = None,
    maintenance_window_end: str | None = None,
    trusted_sources: list[str] | None = None,
    failed_versions: dict[str, str] | None = None,
    retry_cooldown_minutes: int = 30,
) -> list[DiscoveryCandidate]:
    candidates: list[DiscoveryCandidate] = []
    for bundle_path in sorted(mount_root.rglob("signed-bundle.json")):
        public_key = bundle_path.parent / "offline-ota-public.pem"
        envelope = load_signed_manifest(bundle_path)
        policy_result = (
            evaluate_manifest_policy(
                envelope.manifest,
                device_model=str(policy_context["device_model"]),
                agent_version=str(policy_context["agent_version"]),
                active_version=policy_context.get("active_version"),
            )
            if policy_context
            else None
        )
        candidates.append(
            load_candidate(
                bundle_path=bundle_path,
                source=str(bundle_path.parent),
                source_type="usb",
                public_key_path=public_key if public_key.exists() else None,
                policy_result=policy_result,
                rollout_channel=rollout_channel,
                rollout_ring=rollout_ring,
                approved_updates=approved_updates,
                maintenance_window_start=maintenance_window_start,
                maintenance_window_end=maintenance_window_end,
                trusted_sources=trusted_sources,
                failed_versions=failed_versions,
                retry_cooldown_minutes=retry_cooldown_minutes,
            )
        )
    return candidates


def download_http_bundle(
    base_url: str,
    cache_name: str = "http",
    *,
    policy_context: dict[str, str | None] | None = None,
    rollout_channel: str = "stable",
    rollout_ring: str = "general",
    approved_updates: set[str] | None = None,
    maintenance_window_start: str | None = None,
    maintenance_window_end: str | None = None,
    trusted_sources: list[str] | None = None,
    failed_versions: dict[str, str] | None = None,
    retry_cooldown_minutes: int = 30,
) -> DiscoveryCandidate:
    cache_dir = discovery_cache_dir(cache_name)
    if cache_dir.exists():
        shutil.rmtree(cache_dir)
    cache_dir.mkdir(parents=True, exist_ok=True)

    with urlopen(urljoin(base_url.rstrip("/") + "/", "signed-bundle.json")) as response:
        (cache_dir / "signed-bundle.json").write_bytes(response.read())

    for relative_path in ("offline-ota-public.pem", "bundle-index.json"):
        try:
            with urlopen(urljoin(base_url.rstrip("/") + "/", relative_path)) as response:
                (cache_dir / relative_path).write_bytes(response.read())
        except Exception:
            pass

    bundle_index_path = cache_dir / "bundle-index.json"
    artifact_paths: list[str]
    if bundle_index_path.exists():
        index = json.loads(bundle_index_path.read_text())
        artifact_paths = index.get("artifacts", [])
    else:
        envelope: SignedManifestEnvelope = load_signed_manifest(cache_dir / "signed-bundle.json")
        artifact_paths = [artifact.path for artifact in envelope.manifest.artifacts]

    bundle_dir = cache_dir / "bundle"
    bundle_dir.mkdir(parents=True, exist_ok=True)
    for artifact_path in artifact_paths:
        destination = bundle_dir / artifact_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        with urlopen(urljoin(base_url.rstrip("/") + "/", f"bundle/{artifact_path}")) as response:
            destination.write_bytes(response.read())

    public_key = cache_dir / "offline-ota-public.pem"
    envelope = load_signed_manifest(cache_dir / "signed-bundle.json")
    policy_result = (
        evaluate_manifest_policy(
            envelope.manifest,
            device_model=str(policy_context["device_model"]),
            agent_version=str(policy_context["agent_version"]),
            active_version=policy_context.get("active_version"),
        )
        if policy_context
        else None
    )
    return load_candidate(
        bundle_path=cache_dir / "signed-bundle.json",
        source=base_url,
        source_type="http",
        public_key_path=public_key if public_key.exists() else None,
        policy_result=policy_result,
        rollout_channel=rollout_channel,
        rollout_ring=rollout_ring,
        approved_updates=approved_updates,
        maintenance_window_start=maintenance_window_start,
        maintenance_window_end=maintenance_window_end,
        trusted_sources=trusted_sources,
        failed_versions=failed_versions,
        retry_cooldown_minutes=retry_cooldown_minutes,
    )


def select_latest_compatible(candidates: list[dict[str, object]]) -> tuple[int, dict[str, object]] | None:
    compatible_candidates = [
        (index, candidate) for index, candidate in enumerate(candidates) if candidate.get("selectable") is True
    ]
    if not compatible_candidates:
        return None

    compatible_candidates.sort(
        key=lambda item: (
            parse_version(str(item[1]["version"])),
            int(item[1].get("priority", 0)),
            1 if item[1].get("ring") == "canary" else 0,
            1 if item[1].get("channel") == "canary" else 0,
            1 if item[1].get("source_type") == "http" else 0,
            str(item[1].get("source")),
        ),
        reverse=True,
    )
    return compatible_candidates[0]
