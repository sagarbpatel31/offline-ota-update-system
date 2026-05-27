# MVP Implementation Plan

## Completed

- Shared manifest schema using `pydantic`
- Artifact hashing with `sha256`
- Ed25519 key generation, signing, and verification
- Release directory layout scaffold for app-level OTA
- Staged artifact copy, health-check verification, and rollback flow
- JSON device state tracking and dashboard history endpoint

## Next

- Wire installed release content to a real demo service
- Add bundle discovery from USB and local HTTP
- Enforce version compatibility and anti-downgrade policy
- Add tests for install success and rollback scenarios
