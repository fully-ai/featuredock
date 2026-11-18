# Changelog

## [0.1.0] - 2026-11-18

### Added
- Multi-project & multi-environment feature flag platform (`boolean`, `string`, `number`, `json`).
- Deterministic SHA-256 percentage rollout evaluation, user/group targeting, reusable segments, custom rule operators, and emergency kill switches.
- Environment configuration versioning (`ETag` / `If-None-Match` snapshots), RBAC management users, scoped API/SDK tokens, full audit diff logs, and evaluation telemetry.
- Official TypeScript (`sdk/typescript`) and Python (`sdk/python`) SDKs with local TTL cache and telemetry batching.
