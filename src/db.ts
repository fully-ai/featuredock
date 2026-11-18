import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import type { FlagEnvironmentConfig, FlagType, TargetingRule } from "./evaluator.js";

export interface UserRecord {
  id: string;
  username: string;
  role: "admin" | "editor" | "viewer";
}

export class FeatureDockDB {
  public readonly db: DatabaseSync;

  constructor(dataDir: string) {
    fs.mkdirSync(dataDir, { recursive: true });
    this.db = new DatabaseSync(path.join(dataDir, "featuredock.db"));
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA foreign_keys = ON;
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS projects (
        id TEXT PRIMARY KEY,
        key TEXT NOT NULL UNIQUE,
        name TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS environments (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        key TEXT NOT NULL,
        name TEXT NOT NULL,
        sdk_key TEXT NOT NULL UNIQUE,
        config_version INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL,
        UNIQUE(project_id, key),
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS api_tokens (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        token_prefix TEXT NOT NULL,
        token_hash TEXT NOT NULL UNIQUE,
        role TEXT NOT NULL,
        created_by TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS segments (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        name TEXT NOT NULL,
        rules_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(project_id, name),
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS flags (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        key TEXT NOT NULL,
        name TEXT NOT NULL,
        description TEXT NOT NULL DEFAULT '',
        flag_type TEXT NOT NULL,
        default_value_json TEXT NOT NULL,
        rollout_value_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        UNIQUE(project_id, key),
        FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS flag_configs (
        flag_id TEXT NOT NULL,
        environment_id TEXT NOT NULL,
        enabled INTEGER NOT NULL DEFAULT 0,
        kill_switched INTEGER NOT NULL DEFAULT 0,
        rollout_percent REAL NOT NULL DEFAULT 0,
        user_targets_json TEXT NOT NULL DEFAULT '{}',
        group_targets_json TEXT NOT NULL DEFAULT '{}',
        rules_json TEXT NOT NULL DEFAULT '[]',
        salt TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        PRIMARY KEY (flag_id, environment_id),
        FOREIGN KEY (flag_id) REFERENCES flags(id) ON DELETE CASCADE,
        FOREIGN KEY (environment_id) REFERENCES environments(id) ON DELETE CASCADE
      );
      CREATE TABLE IF NOT EXISTS audit_logs (
        id TEXT PRIMARY KEY,
        project_id TEXT NOT NULL,
        actor TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        diff_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS evaluation_history (
        id TEXT PRIMARY KEY,
        environment_id TEXT NOT NULL,
        flag_key TEXT NOT NULL,
        user_id TEXT NOT NULL,
        value_json TEXT NOT NULL,
        reason TEXT NOT NULL,
        evaluated_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_eval_env ON evaluation_history(environment_id, evaluated_at DESC);
    `);
  }

  close(): void {
    this.db.close();
  }

  createUser(username: string, passwordHash: string): UserRecord {
    const cnt = (this.db.prepare("SELECT COUNT(*) AS c FROM users").get() as { c: number }).c;
    const role: UserRecord["role"] = cnt === 0 ? "admin" : "editor";
    const id = crypto.randomUUID();
    this.db
      .prepare("INSERT INTO users (id, username, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(id, username, passwordHash, role, new Date().toISOString());
    return { id, username, role };
  }

  getUserByUsername(username: string) {
    return this.db.prepare("SELECT * FROM users WHERE username = ?").get(username) as
      | { id: string; username: string; password_hash: string; role: UserRecord["role"] }
      | undefined;
  }

  listUsers() {
    return this.db.prepare("SELECT id, username, role, created_at FROM users ORDER BY created_at ASC").all();
  }

  updateUserRole(id: string, role: UserRecord["role"]): boolean {
    return this.db.prepare("UPDATE users SET role = ? WHERE id = ?").run(role, id).changes > 0;
  }

  createApiToken(name: string, role: UserRecord["role"], createdBy: string) {
    const raw = `fd_adm_${crypto.randomBytes(24).toString("hex")}`;
    const hash = crypto.createHash("sha256").update(raw).digest("hex");
    const id = crypto.randomUUID();
    this.db
      .prepare("INSERT INTO api_tokens (id, name, token_prefix, token_hash, role, created_by, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(id, name, raw.slice(0, 14), hash, role, createdBy, new Date().toISOString());
    return { id, name, token_prefix: raw.slice(0, 14), role, token: raw };
  }

  resolveAdminToken(raw: string): UserRecord | undefined {
    const hash = crypto.createHash("sha256").update(raw).digest("hex");
    const row = this.db.prepare("SELECT id, name, role FROM api_tokens WHERE token_hash = ?").get(hash) as
      | { id: string; name: string; role: UserRecord["role"] }
      | undefined;
    if (!row) return undefined;
    return { id: row.id, username: `token:${row.name}`, role: row.role };
  }

  listApiTokens() {
    return this.db.prepare("SELECT id, name, token_prefix, role, created_at FROM api_tokens ORDER BY created_at DESC").all();
  }

  createProject(key: string, name: string, actor: string) {
    const pid = crypto.randomUUID();
    const now = new Date().toISOString();
    this.db.prepare("INSERT INTO projects (id, key, name, created_at) VALUES (?, ?, ?, ?)").run(pid, key, name, now);
    for (const [ek, en] of [
      ["development", "Development"],
      ["staging", "Staging"],
      ["production", "Production"],
    ]) {
      const sdkKey = `fd_sdk_${crypto.randomBytes(20).toString("hex")}`;
      this.db
        .prepare("INSERT INTO environments (id, project_id, key, name, sdk_key, config_version, created_at) VALUES (?, ?, ?, ?, ?, 1, ?)")
        .run(crypto.randomUUID(), pid, ek, en, sdkKey, now);
    }
    this.logAudit(pid, actor, "project.create", key, { name });
    return { project: this.getProject(pid), environments: this.listEnvironments(pid) };
  }

  listProjects() {
    return this.db.prepare("SELECT * FROM projects ORDER BY created_at DESC").all();
  }

  getProject(id: string) {
    return this.db.prepare("SELECT * FROM projects WHERE id = ?").get(id) as Record<string, unknown> | undefined;
  }

  listEnvironments(projectId: string) {
    return this.db.prepare("SELECT * FROM environments WHERE project_id = ? ORDER BY key ASC").all(projectId);
  }

  getEnvironmentBySdkKey(sdkKey: string) {
    return this.db.prepare("SELECT * FROM environments WHERE sdk_key = ?").get(sdkKey) as
      | { id: string; project_id: string; key: string; name: string; sdk_key: string; config_version: number }
      | undefined;
  }

  bumpEnvVersion(envId: string): number {
    this.db.prepare("UPDATE environments SET config_version = config_version + 1 WHERE id = ?").run(envId);
    const row = this.db.prepare("SELECT config_version FROM environments WHERE id = ?").get(envId) as { config_version: number };
    return row.config_version;
  }

  upsertSegment(projectId: string, name: string, rules: TargetingRule[], actor: string) {
    const existing = this.db.prepare("SELECT id FROM segments WHERE project_id = ? AND name = ?").get(projectId, name) as
      | { id: string }
      | undefined;
    const now = new Date().toISOString();
    const rJson = JSON.stringify(rules);
    if (existing) {
      this.db.prepare("UPDATE segments SET rules_json = ? WHERE id = ?").run(rJson, existing.id);
    } else {
      this.db
        .prepare("INSERT INTO segments (id, project_id, name, rules_json, created_at) VALUES (?, ?, ?, ?, ?)")
        .run(crypto.randomUUID(), projectId, name, rJson, now);
    }
    for (const env of this.listEnvironments(projectId) as Array<{ id: string }>) {
      this.bumpEnvVersion(env.id);
    }
    this.logAudit(projectId, actor, "segment.upsert", name, { rules });
    return this.db.prepare("SELECT * FROM segments WHERE project_id = ? AND name = ?").get(projectId, name);
  }

  listSegments(projectId: string): Record<string, TargetingRule[]> {
    const rows = this.db.prepare("SELECT name, rules_json FROM segments WHERE project_id = ?").all(projectId) as Array<{
      name: string;
      rules_json: string;
    }>;
    const out: Record<string, TargetingRule[]> = {};
    for (const r of rows) out[r.name] = JSON.parse(r.rules_json);
    return out;
  }

  createFlag(input: {
    projectId: string;
    key: string;
    name: string;
    description: string;
    flagType: FlagType;
    defaultValue: unknown;
    rolloutValue: unknown;
    actor: string;
  }) {
    const fid = crypto.randomUUID();
    const now = new Date().toISOString();
    this.db
      .prepare(
        "INSERT INTO flags (id, project_id, key, name, description, flag_type, default_value_json, rollout_value_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
      )
      .run(
        fid,
        input.projectId,
        input.key,
        input.name,
        input.description,
        input.flagType,
        JSON.stringify(input.defaultValue),
        JSON.stringify(input.rolloutValue),
        now
      );
    for (const env of this.listEnvironments(input.projectId) as Array<{ id: string }>) {
      this.db
        .prepare(
          "INSERT INTO flag_configs (flag_id, environment_id, enabled, kill_switched, rollout_percent, user_targets_json, group_targets_json, rules_json, salt, updated_at) VALUES (?, ?, 0, 0, 0, '{}', '{}', '[]', ?, ?)"
        )
        .run(fid, env.id, crypto.randomBytes(8).toString("hex"), now);
      this.bumpEnvVersion(env.id);
    }
    this.logAudit(input.projectId, input.actor, "flag.create", input.key, {
      flagType: input.flagType,
      defaultValue: input.defaultValue,
      rolloutValue: input.rolloutValue,
    });
    return this.db.prepare("SELECT * FROM flags WHERE id = ?").get(fid);
  }

  listFlagsWithConfigs(projectId: string, environmentId?: string) {
    const flags = this.db.prepare("SELECT * FROM flags WHERE project_id = ? ORDER BY key ASC").all(projectId) as Array<
      Record<string, unknown>
    >;
    return flags.map((f) => {
      const cfgs = environmentId
        ? this.db
            .prepare("SELECT fc.*, e.key AS env_key FROM flag_configs fc JOIN environments e ON e.id = fc.environment_id WHERE fc.flag_id = ? AND fc.environment_id = ?")
            .all(String(f.id), environmentId)
        : this.db
            .prepare("SELECT fc.*, e.key AS env_key FROM flag_configs fc JOIN environments e ON e.id = fc.environment_id WHERE fc.flag_id = ?")
            .all(String(f.id));
      return {
        ...f,
        default_value: JSON.parse(String(f.default_value_json)),
        rollout_value: JSON.parse(String(f.rollout_value_json)),
        configs: cfgs,
      };
    });
  }

  updateFlagConfig(
    flagId: string,
    envId: string,
    patch: {
      enabled?: boolean;
      killSwitched?: boolean;
      rolloutPercent?: number;
      userTargets?: Record<string, unknown>;
      groupTargets?: Record<string, unknown>;
      rules?: TargetingRule[];
    },
    actor: string
  ) {
    const flag = this.db.prepare("SELECT * FROM flags WHERE id = ?").get(flagId) as
      | { id: string; project_id: string; key: string }
      | undefined;
    const prev = this.db
      .prepare("SELECT * FROM flag_configs WHERE flag_id = ? AND environment_id = ?")
      .get(flagId, envId) as Record<string, unknown> | undefined;
    if (!flag || !prev) return undefined;

    const enabled = patch.enabled !== undefined ? (patch.enabled ? 1 : 0) : Number(prev.enabled);
    const kill = patch.killSwitched !== undefined ? (patch.killSwitched ? 1 : 0) : Number(prev.kill_switched);
    const rollout = patch.rolloutPercent !== undefined ? Math.min(100, Math.max(0, patch.rolloutPercent)) : Number(prev.rollout_percent);
    const uTargets = patch.userTargets !== undefined ? JSON.stringify(patch.userTargets) : String(prev.user_targets_json);
    const gTargets = patch.groupTargets !== undefined ? JSON.stringify(patch.groupTargets) : String(prev.group_targets_json);
    const rules = patch.rules !== undefined ? JSON.stringify(patch.rules) : String(prev.rules_json);
    const now = new Date().toISOString();

    this.db
      .prepare(
        `UPDATE flag_configs SET enabled = ?, kill_switched = ?, rollout_percent = ?, user_targets_json = ?, group_targets_json = ?, rules_json = ?, updated_at = ?
         WHERE flag_id = ? AND environment_id = ?`
      )
      .run(enabled, kill, rollout, uTargets, gTargets, rules, now, flagId, envId);

    const ver = this.bumpEnvVersion(envId);
    this.logAudit(flag.project_id, actor, "flag.update", flag.key, {
      env_id: envId,
      config_version: ver,
      before: { enabled: Boolean(prev.enabled), kill_switched: Boolean(prev.kill_switched), rollout_percent: prev.rollout_percent },
      after: { enabled: Boolean(enabled), kill_switched: Boolean(kill), rollout_percent: rollout },
    });
    return {
      ...this.db.prepare("SELECT * FROM flag_configs WHERE flag_id = ? AND environment_id = ?").get(flagId, envId),
      config_version: ver,
    };
  }

  getEnvironmentSnapshot(envId: string, projectId: string): { version: number; flags: Record<string, FlagEnvironmentConfig> } {
    const env = this.db.prepare("SELECT config_version FROM environments WHERE id = ?").get(envId) as { config_version: number };
    const segs = this.listSegments(projectId);
    const rows = this.db
      .prepare(
        `SELECT f.key, f.flag_type, f.default_value_json, f.rollout_value_json, fc.*
         FROM flags f JOIN flag_configs fc ON fc.flag_id = f.id
         WHERE f.project_id = ? AND fc.environment_id = ?`
      )
      .all(projectId, envId) as Array<Record<string, unknown>>;

    const out: Record<string, FlagEnvironmentConfig> = {};
    for (const r of rows) {
      out[String(r.key)] = {
        flagKey: String(r.key),
        flagType: String(r.flag_type) as FlagType,
        enabled: Number(r.enabled) === 1,
        killSwitched: Number(r.kill_switched) === 1,
        defaultValue: JSON.parse(String(r.default_value_json)),
        rolloutValue: JSON.parse(String(r.rollout_value_json)),
        rolloutPercent: Number(r.rollout_percent),
        userTargets: JSON.parse(String(r.user_targets_json)),
        groupTargets: JSON.parse(String(r.group_targets_json)),
        rules: JSON.parse(String(r.rules_json)),
        segments: segs,
        salt: String(r.salt),
      };
    }
    return { version: env.config_version, flags: out };
  }

  recordEvaluation(envId: string, flagKey: string, userId: string, value: unknown, reason: string) {
    this.db
      .prepare("INSERT INTO evaluation_history (id, environment_id, flag_key, user_id, value_json, reason, evaluated_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(crypto.randomUUID(), envId, flagKey, userId, JSON.stringify(value), reason, new Date().toISOString());
  }

  listEvaluations(envId?: string, limit = 100) {
    if (envId) {
      return this.db.prepare("SELECT * FROM evaluation_history WHERE environment_id = ? ORDER BY evaluated_at DESC LIMIT ?").all(envId, limit);
    }
    return this.db.prepare("SELECT * FROM evaluation_history ORDER BY evaluated_at DESC LIMIT ?").all(limit);
  }

  logAudit(projectId: string, actor: string, action: string, target: string, diff: Record<string, unknown>) {
    this.db
      .prepare("INSERT INTO audit_logs (id, project_id, actor, action, target, diff_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(crypto.randomUUID(), projectId, actor, action, target, JSON.stringify(diff), new Date().toISOString());
  }

  listAudit(projectId: string) {
    return this.db.prepare("SELECT * FROM audit_logs WHERE project_id = ? ORDER BY created_at DESC LIMIT 100").all(projectId);
  }
}
