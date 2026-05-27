# Roadmap

## Phase 1: Foundations

- Finalize manifest schema
- Implement bundle creation
- Add signature verification
- Add version and device compatibility checks

## Phase 2: Device Update Flow

- Implement release staging
- Implement active symlink switching
- Add systemd restart integration
- Add health check evaluation

## Phase 3: Rollback and Audit

- Persist update state machine
- Add rollback on failed health checks
- Write update history and error logs

## Phase 4: Delivery Paths

- Add USB discovery
- Add local HTTP discovery
- Add manual update trigger from dashboard

## Phase 5: Demo and Hardening

- Add bad update injection scenario
- Record demo walkthrough
- Add tests for manifest validation and rollback logic
