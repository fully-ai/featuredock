import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import express, { type NextFunction, type Request, type Response } from "express";
import helmet from "helmet";
import jwt from "jsonwebtoken";
import { FeatureDockDB, type UserRecord } from "./db.js";
import { evaluateFlag, type EvaluationContext, type FlagType } from "./evaluator.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.resolve(__dirname, "../public");

export interface AuthedRequest extends Request {
  user?: UserRecord;
}

function hashPassword(password: string): string {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, stored: string): boolean {
  const [salt, expected] = stored.split(":");
  if (!salt || !expected) return false;
  const derived = crypto.scryptSync(password, salt, 64);
  const expBuf = Buffer.from(expected, "hex");
  return derived.length === expBuf.length && crypto.timingSafeEqual(derived, expBuf);
}

export function createFeatureDockApp(opts: { dataDir?: string; jwtSecret?: string } = {}) {
  const dataDir = path.resolve(opts.dataDir ?? process.env.FEATUREDOCK_DATA_DIR ?? "./data");
  const jwtSecret = opts.jwtSecret ?? process.env.FEATUREDOCK_JWT_SECRET ?? crypto.randomBytes(32).toString("hex");
  const db = new FeatureDockDB(dataDir);

  const app = express();
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(express.json({ limit: "512kb" }));

  const requireRole = (minRole: UserRecord["role"] = "viewer") => {
    const rank = { viewer: 1, editor: 2, admin: 3 };
    return (req: AuthedRequest, res: Response, next: NextFunction) => {
      const hdr = req.headers.authorization ?? "";
      if (!hdr.startsWith("Bearer ")) {
        res.status(401).json({ error: "Unauthorized" });
        return;
      }
      const raw = hdr.slice(7).trim();
      if (raw.startsWith("fd_adm_")) {
        const tokUser = db.resolveAdminToken(raw);
        if (!tokUser || rank[tokUser.role] < rank[minRole]) {
          res.status(tokUser ? 403 : 401).json({ error: tokUser ? "Forbidden" : "Invalid token" });
          return;
        }
        req.user = tokUser;
        next();
        return;
      }
      try {
        const user = jwt.verify(raw, jwtSecret) as UserRecord;
        if (rank[user.role] < rank[minRole]) {
          res.status(403).json({ error: "Forbidden" });
          return;
        }
        req.user = user;
        next();
      } catch {
        res.status(401).json({ error: "Invalid token" });
      }
    };
  };

  function resolveSdkEnv(req: Request, res: Response) {
    const hdr = req.headers.authorization ?? "";
    const sdkKey = String(req.headers["x-sdk-key"] ?? (hdr.startsWith("Bearer ") ? hdr.slice(7) : "")).trim();
    const env = db.getEnvironmentBySdkKey(sdkKey);
    if (!env) {
      res.status(401).json({ error: "Invalid SDK key" });
      return undefined;
    }
    return env;
  }

  app.get("/api/health", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.post("/api/auth/register", (req, res) => {
    const username = String(req.body?.username ?? "").trim();
    const password = String(req.body?.password ?? "");
    if (!/^[a-zA-Z0-9_-]{3,32}$/.test(username) || password.length < 8) {
      res.status(400).json({ error: "Username (3-32 chars) and password (>= 8 chars) required" });
      return;
    }
    if (db.getUserByUsername(username)) {
      res.status(409).json({ error: "Username exists" });
      return;
    }
    const user = db.createUser(username, hashPassword(password));
    const token = jwt.sign(user, jwtSecret, { expiresIn: "24h" });
    res.status(201).json({ token, user });
  });

  app.post("/api/auth/login", (req, res) => {
    const username = String(req.body?.username ?? "").trim();
    const password = String(req.body?.password ?? "");
    const u = db.getUserByUsername(username);
    if (!u || !verifyPassword(password, u.password_hash)) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }
    const user: UserRecord = { id: u.id, username: u.username, role: u.role };
    res.json({ token: jwt.sign(user, jwtSecret, { expiresIn: "24h" }), user });
  });

  app.get("/api/users", requireRole("admin"), (_req, res) => {
    res.json({ users: db.listUsers() });
  });

  app.patch("/api/users/:id/role", requireRole("admin"), (req, res) => {
    const role = String(req.body?.role ?? "") as UserRecord["role"];
    if (!["viewer", "editor", "admin"].includes(role)) {
      res.status(400).json({ error: "Invalid role" });
      return;
    }
    if (!db.updateUserRole(String(req.params.id), role)) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    res.json({ status: "updated", role });
  });

  app.get("/api/tokens", requireRole("admin"), (_req, res) => {
    res.json({ tokens: db.listApiTokens() });
  });

  app.post("/api/tokens", requireRole("admin"), (req: AuthedRequest, res) => {
    const name = String(req.body?.name ?? "").trim();
    const role = String(req.body?.role ?? "editor") as UserRecord["role"];
    if (!name || !["viewer", "editor", "admin"].includes(role)) {
      res.status(400).json({ error: "Valid name and role required" });
      return;
    }
    res.status(201).json(db.createApiToken(name, role, req.user!.username));
  });

  app.get("/api/projects", requireRole("viewer"), (_req, res) => {
    res.json({ projects: db.listProjects() });
  });

  app.post("/api/projects", requireRole("admin"), (req: AuthedRequest, res) => {
    const key = String(req.body?.key ?? "").trim().toLowerCase();
    const name = String(req.body?.name ?? "").trim();
    if (!/^[a-z0-9_-]{2,40}$/.test(key) || !name) {
      res.status(400).json({ error: "Valid project key and name required" });
      return;
    }
    try {
      res.status(201).json(db.createProject(key, name, req.user!.username));
    } catch {
      res.status(409).json({ error: "Project key already exists" });
    }
  });

  app.get("/api/projects/:id/environments", requireRole("viewer"), (req, res) => {
    res.json({ environments: db.listEnvironments(String(req.params.id)) });
  });

  app.get("/api/projects/:id/segments", requireRole("viewer"), (req, res) => {
    res.json({ segments: db.listSegments(String(req.params.id)) });
  });

  app.post("/api/projects/:id/segments", requireRole("editor"), (req: AuthedRequest, res) => {
    const name = String(req.body?.name ?? "").trim();
    const rules = Array.isArray(req.body?.rules) ? req.body.rules : [];
    if (!name || !rules.length) {
      res.status(400).json({ error: "Segment name and rules array required" });
      return;
    }
    res.status(201).json(db.upsertSegment(String(req.params.id), name, rules, req.user!.username));
  });

  app.get("/api/projects/:id/flags", requireRole("viewer"), (req, res) => {
    const envId = typeof req.query.env_id === "string" ? req.query.env_id : undefined;
    res.json({ flags: db.listFlagsWithConfigs(String(req.params.id), envId) });
  });

  app.post("/api/projects/:id/flags", requireRole("editor"), (req: AuthedRequest, res) => {
    const pid = String(req.params.id);
    if (!db.getProject(pid)) {
      res.status(404).json({ error: "Project not found" });
      return;
    }
    const key = String(req.body?.key ?? "").trim();
    const name = String(req.body?.name ?? key).trim();
    const flagType = String(req.body?.flag_type ?? "boolean") as FlagType;
    if (!/^[a-zA-Z0-9._-]{2,64}$/.test(key) || !["boolean", "string", "number", "json"].includes(flagType)) {
      res.status(400).json({ error: "Valid flag key and flag_type required" });
      return;
    }
    const defaultValue = req.body?.default_value !== undefined ? req.body.default_value : false;
    const rolloutValue = req.body?.rollout_value !== undefined ? req.body.rollout_value : true;
    try {
      const flag = db.createFlag({
        projectId: pid,
        key,
        name,
        description: String(req.body?.description ?? ""),
        flagType,
        defaultValue,
        rolloutValue,
        actor: req.user!.username,
      });
      res.status(201).json(flag);
    } catch {
      res.status(409).json({ error: "Flag key already exists in project" });
    }
  });

  app.patch("/api/flags/:flagId/environments/:envId", requireRole("editor"), (req: AuthedRequest, res) => {
    const updated = db.updateFlagConfig(
      String(req.params.flagId),
      String(req.params.envId),
      {
        enabled: req.body?.enabled !== undefined ? Boolean(req.body.enabled) : undefined,
        killSwitched: req.body?.kill_switched !== undefined ? Boolean(req.body.kill_switched) : undefined,
        rolloutPercent: req.body?.rollout_percent !== undefined ? Number(req.body.rollout_percent) : undefined,
        userTargets: req.body?.user_targets,
        groupTargets: req.body?.group_targets,
        rules: req.body?.rules,
      },
      req.user!.username
    );
    if (!updated) {
      res.status(404).json({ error: "Flag or environment not found" });
      return;
    }
    res.json(updated);
  });

  app.get("/api/projects/:id/audit", requireRole("viewer"), (req, res) => {
    res.json({ audit: db.listAudit(String(req.params.id)) });
  });

  app.get("/api/evaluations", requireRole("viewer"), (req, res) => {
    const envId = typeof req.query.env_id === "string" ? req.query.env_id : undefined;
    res.json({ evaluations: db.listEvaluations(envId) });
  });

  // SDK Endpoints (Authenticated via fd_sdk_... key)
  app.get("/api/sdk/v1/snapshot", (req, res) => {
    const env = resolveSdkEnv(req, res);
    if (!env) return;
    const etag = `"v${env.config_version}"`;
    if (req.headers["if-none-match"] === etag) {
      res.status(304).end();
      return;
    }
    const snap = db.getEnvironmentSnapshot(env.id, env.project_id);
    res.setHeader("ETag", etag);
    res.json({ environment: env.key, config_version: snap.version, flags: snap.flags });
  });

  app.post("/api/sdk/v1/evaluate", (req, res) => {
    const env = resolveSdkEnv(req, res);
    if (!env) return;
    const flagKey = String(req.body?.flag_key ?? "").trim();
    const context = (req.body?.context ?? {}) as EvaluationContext;
    const snap = db.getEnvironmentSnapshot(env.id, env.project_id);
    const cfg = snap.flags[flagKey];
    if (!cfg) {
      res.status(404).json({ error: "Flag not found in environment", config_version: snap.version });
      return;
    }
    const result = evaluateFlag(cfg, context);
    db.recordEvaluation(env.id, flagKey, String(context.userId ?? "anonymous"), result.value, result.reason);
    res.json({ ...result, config_version: snap.version });
  });

  app.post("/api/sdk/v1/telemetry", (req, res) => {
    const env = resolveSdkEnv(req, res);
    if (!env) return;
    const events = Array.isArray(req.body?.events) ? req.body.events : [];
    for (const ev of events.slice(0, 200)) {
      if (ev?.flagKey) {
        db.recordEvaluation(
          env.id,
          String(ev.flagKey),
          String(ev.userId ?? "anonymous"),
          ev.value ?? null,
          String(ev.reason ?? "sdk_cache")
        );
      }
    }
    res.status(202).json({ accepted: Math.min(events.length, 200) });
  });

  app.use(express.static(PUBLIC_DIR));
  return { app, db };
}
