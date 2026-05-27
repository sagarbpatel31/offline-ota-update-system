from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from pydantic import BaseModel, Field


def canonical_json(payload: dict) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class ArtifactManifest(BaseModel):
    name: str
    path: str
    sha256: str
    size_bytes: int


class HealthCheck(BaseModel):
    type: str = "http"
    endpoint: str
    timeout_seconds: int = 30


class BundleManifest(BaseModel):
    version: str
    device_model: str
    minimum_agent_version: str
    artifacts: list[ArtifactManifest]
    health_check: HealthCheck


class SignedManifestEnvelope(BaseModel):
    manifest: BundleManifest
    signature: str = Field(description="Base64-encoded Ed25519 signature")
    signing_algorithm: str = "ed25519"


@dataclass
class VerifiedBundle:
    envelope: SignedManifestEnvelope
    manifest_path: Path


def encode_signature(signature: bytes) -> str:
    return base64.b64encode(signature).decode("utf-8")


def decode_signature(signature: str) -> bytes:
    return base64.b64decode(signature.encode("utf-8"))


def manifest_payload(manifest: BundleManifest) -> bytes:
    return canonical_json(manifest.model_dump())


def load_signed_manifest(path: Path) -> SignedManifestEnvelope:
    return SignedManifestEnvelope.model_validate(json.loads(path.read_text()))

