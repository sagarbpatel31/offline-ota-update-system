from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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


def within_maintenance_window(
    *,
    now: datetime,
    window_start: str | None,
    window_end: str | None,
) -> bool:
    if not window_start or not window_end:
        return True

    start_hour, start_minute = [int(part) for part in window_start.split(":", maxsplit=1)]
    end_hour, end_minute = [int(part) for part in window_end.split(":", maxsplit=1)]
    current_minutes = now.hour * 60 + now.minute
    start_minutes = start_hour * 60 + start_minute
    end_minutes = end_hour * 60 + end_minute

    if start_minutes <= end_minutes:
        return start_minutes <= current_minutes <= end_minutes
    return current_minutes >= start_minutes or current_minutes <= end_minutes


def source_is_trusted(source: str, *, trusted_sources: list[str]) -> bool:
    if not trusted_sources:
        return True
    return any(source.startswith(prefix) for prefix in trusted_sources)


def parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def timestamp_active(value: str | None, *, now: datetime) -> bool:
    timestamp = parse_timestamp(value)
    if not timestamp:
        return False
    comparison_now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return comparison_now < timestamp


def cooldown_active(
    *,
    version: str,
    failed_versions: dict[str, str],
    cooldown_minutes: int,
    now: datetime,
) -> bool:
    timestamp = parse_timestamp(failed_versions.get(version))
    if not timestamp:
        return False
    comparison_now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return comparison_now < timestamp + timedelta(minutes=cooldown_minutes)


def adaptive_cooldown_minutes(
    *,
    base_minutes: int,
    failure_count: int,
    max_minutes: int = 24 * 60,
) -> int:
    scaled = base_minutes * (2 ** max(failure_count - 1, 0))
    return min(scaled, max_minutes)


def adaptive_source_backoff_minutes(
    *,
    base_minutes: int,
    consecutive_failures: int,
    max_minutes: int = 12 * 60,
) -> int:
    scaled = base_minutes * (2 ** max(consecutive_failures - 1, 0))
    return min(scaled, max_minutes)


def source_backoff_active(entry: dict[str, object] | None, *, now: datetime) -> bool:
    if not entry:
        return False
    return timestamp_active(entry.get("backoff_until"), now=now)


def source_quarantined(entry: dict[str, object] | None, *, now: datetime) -> bool:
    if not entry:
        return False
    return timestamp_active(entry.get("quarantined_until"), now=now)


def source_block_reason(entry: dict[str, object] | None, *, now: datetime) -> str | None:
    if source_quarantined(entry, now=now):
        return "source is quarantined"
    if source_backoff_active(entry, now=now):
        return "source fetch backoff active"
    return None


def resolve_source_policy(
    source: str,
    source_policies: dict[str, dict[str, object]] | None,
) -> dict[str, object]:
    if not source_policies:
        return {}
    matched_prefixes = [prefix for prefix in source_policies if source.startswith(prefix)]
    if not matched_prefixes:
        return {}
    best_prefix = max(matched_prefixes, key=len)
    return dict(source_policies[best_prefix])


def poll_interval_active(
    *,
    last_attempted_at: str | None,
    poll_interval_minutes: int,
    now: datetime,
) -> bool:
    if poll_interval_minutes <= 0:
        return False
    timestamp = parse_timestamp(last_attempted_at)
    if not timestamp:
        return False
    comparison_now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return comparison_now < timestamp + timedelta(minutes=poll_interval_minutes)


def affinity_active(
    *,
    last_success_at: str | None,
    ttl_hours: int,
    now: datetime,
) -> bool:
    if ttl_hours <= 0:
        return False
    timestamp = parse_timestamp(last_success_at)
    if not timestamp:
        return False
    comparison_now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    return comparison_now <= timestamp + timedelta(hours=ttl_hours)


def decayed_channel_success_rate(
    *,
    successes: int,
    failures: int,
    last_failure_at: str | None,
    decay_threshold: int,
    decay_penalty: int,
    now: datetime,
) -> int:
    total_attempts = successes + failures
    base_rate = int((successes * 100) / total_attempts) if total_attempts else 0
    if failures < decay_threshold:
        return base_rate
    recent_failure = parse_timestamp(last_failure_at)
    if not recent_failure:
        return max(0, base_rate - decay_penalty)
    comparison_now = now if now.tzinfo else now.replace(tzinfo=timezone.utc)
    if comparison_now <= recent_failure + timedelta(hours=24):
        return max(0, base_rate - decay_penalty)
    return base_rate


def degraded_bundle_channel(
    *,
    failures: int,
    threshold: int,
) -> bool:
    return failures >= threshold


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
