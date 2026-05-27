from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from ota.bundle import BundleManifest, decode_signature, encode_signature, manifest_payload


def generate_keypair(private_key_path: Path, public_key_path: Path) -> None:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)

    private_key_path.write_bytes(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    public_key_path.write_bytes(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )


def load_private_key(path: Path) -> Ed25519PrivateKey:
    return serialization.load_pem_private_key(path.read_bytes(), password=None)


def load_public_key(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())


def sign_manifest(manifest: BundleManifest, private_key_path: Path) -> str:
    signature = load_private_key(private_key_path).sign(manifest_payload(manifest))
    return encode_signature(signature)


def verify_manifest_signature(
    manifest: BundleManifest,
    signature: str,
    public_key_path: Path,
) -> None:
    load_public_key(public_key_path).verify(
        decode_signature(signature),
        manifest_payload(manifest),
    )
