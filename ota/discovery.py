from __future__ import annotations

import json
import shutil
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin
from urllib.request import urlopen

from ota.bundle import SignedManifestEnvelope, load_signed_manifest


@dataclass
class DiscoveryCandidate:
    source: str
    source_type: str
    bundle_path: Path
    bundle_dir: Path
    public_key_path: Path | None
    version: str
    device_model: str

    def as_dict(self) -> dict[str, str | None]:
        return {
            "source": self.source,
            "source_type": self.source_type,
            "bundle_path": str(self.bundle_path),
            "bundle_dir": str(self.bundle_dir),
            "public_key_path": str(self.public_key_path) if self.public_key_path else None,
            "version": self.version,
            "device_model": self.device_model,
        }


def discovery_root() -> Path:
    return Path("artifacts/discovery")


def discovery_cache_dir(name: str) -> Path:
    return discovery_root() / name


def load_candidate(bundle_path: Path, source: str, source_type: str, public_key_path: Path | None = None) -> DiscoveryCandidate:
    envelope = load_signed_manifest(bundle_path)
    manifest = envelope.manifest
    return DiscoveryCandidate(
        source=source,
        source_type=source_type,
        bundle_path=bundle_path,
        bundle_dir=bundle_path.parent / "bundle",
        public_key_path=public_key_path,
        version=manifest.version,
        device_model=manifest.device_model,
    )


def discover_usb_candidates(mount_root: Path) -> list[DiscoveryCandidate]:
    candidates: list[DiscoveryCandidate] = []
    for bundle_path in sorted(mount_root.rglob("signed-bundle.json")):
        public_key = bundle_path.parent / "offline-ota-public.pem"
        candidates.append(
            load_candidate(
                bundle_path=bundle_path,
                source=str(bundle_path.parent),
                source_type="usb",
                public_key_path=public_key if public_key.exists() else None,
            )
        )
    return candidates


def download_http_bundle(base_url: str, cache_name: str = "http") -> DiscoveryCandidate:
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
    return load_candidate(
        bundle_path=cache_dir / "signed-bundle.json",
        source=base_url,
        source_type="http",
        public_key_path=public_key if public_key.exists() else None,
    )
