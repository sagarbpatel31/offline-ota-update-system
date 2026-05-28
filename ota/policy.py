from __future__ import annotations

from dataclasses import dataclass

from ota.bundle import BundleManifest


def parse_version(value: str) -> tuple[int, ...]:
    parts: list[int] = []
    for piece in value.strip().split("."):
        digits = "".join(character for character in piece if character.isdigit())
        parts.append(int(digits or "0"))
    return tuple(parts)


def compare_versions(left: str, right: str) -> int:
    left_parts = parse_version(left)
    right_parts = parse_version(right)
    max_length = max(len(left_parts), len(right_parts))
    padded_left = left_parts + (0,) * (max_length - len(left_parts))
    padded_right = right_parts + (0,) * (max_length - len(right_parts))
    if padded_left < padded_right:
        return -1
    if padded_left > padded_right:
        return 1
    return 0


@dataclass
class PolicyResult:
    allowed: bool
    reason: str | None = None


def evaluate_manifest_policy(
    manifest: BundleManifest,
    *,
    device_model: str,
    agent_version: str,
    active_version: str | None,
) -> PolicyResult:
    if manifest.device_model != device_model:
        return PolicyResult(
            allowed=False,
            reason=f"device model mismatch: bundle targets {manifest.device_model}, device is {device_model}",
        )

    if compare_versions(agent_version, manifest.minimum_agent_version) < 0:
        return PolicyResult(
            allowed=False,
            reason=(
                f"agent version {agent_version} is below minimum required "
                f"{manifest.minimum_agent_version}"
            ),
        )

    if active_version and compare_versions(manifest.version, active_version) <= 0:
        return PolicyResult(
            allowed=False,
            reason=(
                f"anti-downgrade policy rejected version {manifest.version}; "
                f"active version is {active_version}"
            ),
        )

    return PolicyResult(allowed=True)
