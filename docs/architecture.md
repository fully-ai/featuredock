# FeatureDock Architecture

1. **Control Plane (`src/app.ts`, `src/db.ts`)**: Stores projects, environments (`sdk_key` + `config_version`), flags (`boolean`, `string`, `number`, `json`), segments, RBAC users, API tokens, before/after audit diffs, and evaluation telemetry in SQLite (`node:sqlite`, WAL mode).
2. **Evaluation Engine (`src/evaluator.ts`)**: Evaluates kill switch -> enabled -> user target -> group target -> ordered rules & segments -> SHA-256 deterministic percentage rollout (`0.01%` granularity) -> default value.
3. **SDKs (`sdk/typescript`, `sdk/python`)**: Fetch versioned snapshots (`ETag` / `If-None-Match` `304`) with TTL caching, evaluate deterministically in-process, and report telemetry back to `/api/sdk/v1/telemetry`.
