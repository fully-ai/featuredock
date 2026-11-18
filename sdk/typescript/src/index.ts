import crypto from "node:crypto";

export interface FeatureDockConfig {
  apiUrl: string;
  sdkKey: string;
  cacheTtlMs?: number;
}

export interface EvaluationContext {
  userId?: string;
  groupId?: string;
  groups?: string[];
  attributes?: Record<string, unknown>;
}

interface TargetingRule {
  attribute: string;
  operator: string;
  value: unknown;
  serveValue: unknown;
}

interface FlagSnapshotEntry {
  flagKey: string;
  enabled: boolean;
  killSwitched: boolean;
  defaultValue: unknown;
  rolloutValue: unknown;
  rolloutPercent: number;
  userTargets: Record<string, unknown>;
  groupTargets: Record<string, unknown>;
  rules: TargetingRule[];
  segments: Record<string, TargetingRule[]>;
  salt: string;
}

export class FeatureDock {
  private readonly apiUrl: string;
  private readonly sdkKey: string;
  private readonly cacheTtlMs: number;
  private etag = "";
  private lastFetch = 0;
  private flags: Record<string, FlagSnapshotEntry> = {};

  constructor(cfg: FeatureDockConfig) {
    this.apiUrl = cfg.apiUrl.replace(/\/+$/, "");
    this.sdkKey = cfg.sdkKey;
    this.cacheTtlMs = cfg.cacheTtlMs ?? 15_000;
  }

  private async ensureSnapshot(): Promise<void> {
    if (Date.now() - this.lastFetch < this.cacheTtlMs && Object.keys(this.flags).length > 0) {
      return;
    }
    const headers: Record<string, string> = { Authorization: `Bearer ${this.sdkKey}` };
    if (this.etag) headers["If-None-Match"] = this.etag;
    const res = await fetch(`${this.apiUrl}/api/sdk/v1/snapshot`, { headers });
    this.lastFetch = Date.now();
    if (res.status === 304) return;
    if (!res.ok) throw new Error(`FeatureDock SDK HTTP ${res.status}`);
    this.etag = res.headers.get("etag") ?? "";
    const data = (await res.json()) as { flags: Record<string, FlagSnapshotEntry> };
    this.flags = data.flags ?? {};
  }

  private evaluateLocal(cfg: FlagSnapshotEntry, ctx: EvaluationContext): { value: unknown; reason: string } {
    if (cfg.killSwitched) return { value: cfg.defaultValue, reason: "kill_switch" };
    if (!cfg.enabled) return { value: cfg.defaultValue, reason: "disabled" };
    if (ctx.userId && Object.prototype.hasOwnProperty.call(cfg.userTargets, ctx.userId)) {
      return { value: cfg.userTargets[ctx.userId], reason: "user_target" };
    }
    const groups = [...(ctx.groupId ? [ctx.groupId] : []), ...(ctx.groups ?? [])];
    for (const g of groups) {
      if (Object.prototype.hasOwnProperty.call(cfg.groupTargets, g)) {
        return { value: cfg.groupTargets[g], reason: "group_target" };
      }
    }
    for (const r of cfg.rules ?? []) {
      if (this.matchRule(r, ctx, cfg.segments ?? {})) return { value: r.serveValue, reason: "rule_match" };
    }
    if (cfg.rolloutPercent >= 100) return { value: cfg.rolloutValue, reason: "rollout_100" };
    if (cfg.rolloutPercent > 0 && ctx.userId) {
      const digest = crypto.createHash("sha256").update(`${cfg.salt}:${cfg.flagKey}:${ctx.userId}`).digest();
      if (digest.readUInt32BE(0) % 10000 < Math.round(cfg.rolloutPercent * 100)) {
        return { value: cfg.rolloutValue, reason: "percentage_rollout" };
      }
    }
    return { value: cfg.defaultValue, reason: "default" };
  }

  private matchRule(r: TargetingRule, ctx: EvaluationContext, segs: Record<string, TargetingRule[]>): boolean {
    if (r.operator === "segment") {
      const rules = segs[String(r.value ?? "")] ?? [];
      return rules.length > 0 && rules.every((sr) => this.matchRule(sr, ctx, segs));
    }
    const actual = r.attribute === "userId" ? ctx.userId : r.attribute === "groupId" ? ctx.groupId : ctx.attributes?.[r.attribute];
    if (r.operator === "eq") return actual === r.value;
    if (r.operator === "neq") return actual !== r.value;
    if (r.operator === "in") return Array.isArray(r.value) && r.value.includes(actual);
    if (r.operator === "contains") return typeof actual === "string" && actual.includes(String(r.value ?? ""));
    return false;
  }

  private async emitTelemetry(flagKey: string, userId: string | undefined, value: unknown, reason: string): Promise<void> {
    await fetch(`${this.apiUrl}/api/sdk/v1/telemetry`, {
      method: "POST",
      headers: { Authorization: `Bearer ${this.sdkKey}`, "Content-Type": "application/json" },
      body: JSON.stringify({ events: [{ flagKey, userId: userId ?? "anonymous", value, reason }] }),
    }).catch(() => {});
  }

  async getVariation<T = unknown>(flagKey: string, context: EvaluationContext = {}, defaultValue?: T): Promise<T> {
    await this.ensureSnapshot();
    const cfg = this.flags[flagKey];
    if (!cfg) return defaultValue as T;
    const res = this.evaluateLocal(cfg, context);
    await this.emitTelemetry(flagKey, context.userId, res.value, res.reason);
    return res.value as T;
  }

  async isEnabled(flagKey: string, context: EvaluationContext = {}, defaultValue = false): Promise<boolean> {
    const val = await this.getVariation(flagKey, context, defaultValue);
    return Boolean(val);
  }
}
