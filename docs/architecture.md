# Architecture

## Components

- **Signer** builds an update bundle, writes manifest metadata, and signs release artifacts
- **Agent** runs on-device, discovers local bundles, validates them, stages them, switches releases, and manages rollback
- **Dashboard** exposes device state, version, and update history to a local operator
- **Release Store** is a USB mount or local HTTP endpoint that hosts bundles

## Update Lifecycle

1. Discover candidate bundle
2. Verify manifest signature
3. Verify artifact hashes and compatibility
4. Stage release into inactive location
5. Switch active release pointer
6. Restart service and run health checks
7. Mark success or trigger rollback

## MVP Design Choices

- Start with **app-level OTA**, not full rootfs A/B
- Use **release directories + active symlink** for safe switching
- Use **FastAPI** for the dashboard and local control plane
- Keep bundle delivery local-first: USB and HTTP on a trusted LAN
- Use **Ed25519** signatures over a canonicalized JSON manifest
- Verify artifact hashes before any staging action begins

## v2 Expansion

- A/B root filesystem updates
- Delta bundles
- Multi-device rollout rings
- Stronger key management
- Signed audit history
