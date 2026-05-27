# MVP Implementation Plan

## Completed

- Shared manifest schema using `pydantic`
- Artifact hashing with `sha256`
- Ed25519 key generation, signing, and verification
- Release directory layout scaffold for app-level OTA

## Next

- Copy verified artifacts into staged release directories
- Add active symlink promotion and previous-release tracking
- Add health-check execution and rollback on failure
- Persist update lifecycle history in JSONL format
- Wire the dashboard to real agent state
