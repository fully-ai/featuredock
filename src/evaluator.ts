import crypto from "node:crypto";

export type FlagType = "boolean" | "string" | "number" | "json";

export interface EvaluationContext {
  userId?: string;
  groupId?: string;
  groups?: string[];
  attributes?: Record<string, unknown>;
}

export interface TargetingRule {
  attribute: string;
  operator: "eq" | "neq" | "in" | "not_in" | "contains" | "gt" | "lt" | "regex" | "segment";
  value: unknown;
  serveValue: unknown;
}

export interface FlagEnvironmentConfig {
  flagKey: string;
  flagType: FlagType;
  enabled: boolean;
  killSwitched: boolean;
  defaultValue: unknown;
  rolloutValue: unknown;
  rolloutPercent: number; // 0..100
  userTargets: Record<string, unknown>;
  groupTargets: Record<string, unknown>;
  rules: TargetingRule[];
  segments: Record<string, TargetingRule[]>;
  salt: string;
}

export interface EvaluationResult {
  flagKey: string;
  value: unknown;
  reason: string;
}

export function rolloutBucket(salt: string, flagKey: string, subject: string): number {
  const digest = crypto.createHash("sha256").update(`${salt}:${flagKey}:${subject}`).digest();
  const num = digest.readUInt32BE(0);
  return num % 10000; // 0..9999 (0.01% granularity)
}

function getContextAttr(ctx: EvaluationContext, attr: string): unknown {
  if (attr === "userId") return ctx.userId;
  if (attr === "groupId") return ctx.groupId;
  if (attr === "groups") return ctx.groups;
  return ctx.attributes?.[attr];
}

function matchCondition(rule: TargetingRule, ctx: EvaluationContext, segments: Record<string, TargetingRule[]>): boolean {
  if (rule.operator === "segment") {
    const segName = String(rule.value ?? "");
    const segRules = segments[segName] ?? [];
    return segRules.length > 0 && segRules.every((sr) => matchCondition(sr, ctx, segments));
  }
  const actual = getContextAttr(ctx, rule.attribute);
  switch (rule.operator) {
    case "eq":
      return actual === rule.value;
    case "neq":
      return actual !== rule.value;
    case "in":
      return Array.isArray(rule.value) && rule.value.includes(actual);
    case "not_in":
      return Array.isArray(rule.value) && !rule.value.includes(actual);
    case "contains":
      if (Array.isArray(actual)) return actual.includes(rule.value);
      return typeof actual === "string" && actual.includes(String(rule.value ?? ""));
    case "gt":
      return typeof actual === "number" && typeof rule.value === "number" && actual > rule.value;
    case "lt":
      return typeof actual === "number" && typeof rule.value === "number" && actual < rule.value;
    case "regex": {
      const pattern = String(rule.value ?? "");
      if (pattern.length > 128 || typeof actual !== "string") return false;
      try {
        return new RegExp(pattern).test(actual);
      } catch {
        return false;
      }
    }
    default:
      return false;
  }
}

export function evaluateFlag(cfg: FlagEnvironmentConfig, ctx: EvaluationContext = {}): EvaluationResult {
  if (cfg.killSwitched) {
    return { flagKey: cfg.flagKey, value: cfg.defaultValue, reason: "kill_switch" };
  }
  if (!cfg.enabled) {
    return { flagKey: cfg.flagKey, value: cfg.defaultValue, reason: "disabled" };
  }
  if (ctx.userId && Object.prototype.hasOwnProperty.call(cfg.userTargets, ctx.userId)) {
    return { flagKey: cfg.flagKey, value: cfg.userTargets[ctx.userId], reason: "user_target" };
  }
  const candidateGroups = [
    ...(ctx.groupId ? [ctx.groupId] : []),
    ...(Array.isArray(ctx.groups) ? ctx.groups : []),
  ];
  for (const g of candidateGroups) {
    if (Object.prototype.hasOwnProperty.call(cfg.groupTargets, g)) {
      return { flagKey: cfg.flagKey, value: cfg.groupTargets[g], reason: "group_target" };
    }
  }
  for (const rule of cfg.rules) {
    if (matchCondition(rule, ctx, cfg.segments)) {
      return { flagKey: cfg.flagKey, value: rule.serveValue, reason: "rule_match" };
    }
  }
  if (cfg.rolloutPercent >= 100) {
    return { flagKey: cfg.flagKey, value: cfg.rolloutValue, reason: "rollout_100" };
  }
  if (cfg.rolloutPercent > 0 && ctx.userId) {
    const bucket = rolloutBucket(cfg.salt, cfg.flagKey, ctx.userId);
    if (bucket < Math.round(cfg.rolloutPercent * 100)) {
      return { flagKey: cfg.flagKey, value: cfg.rolloutValue, reason: "percentage_rollout" };
    }
  }
  return { flagKey: cfg.flagKey, value: cfg.defaultValue, reason: "default" };
}
