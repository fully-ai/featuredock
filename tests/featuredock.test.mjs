import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { after, before, test } from "node:test";
import { createFeatureDockApp } from "../dist/app.js";
import { FeatureDock } from "../sdk/typescript/dist/index.js";

let tmpDir;
let server;
let db;
let baseUrl;

before(async () => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "featuredock-test-"));
  const created = createFeatureDockApp({
    dataDir: tmpDir,
    jwtSecret: "featuredock-test-jwt-secret",
  });
  db = created.db;
  server = await new Promise((resolve) => {
    const s = created.app.listen(0, "127.0.0.1", () => resolve(s));
  });
  baseUrl = `http://127.0.0.1:${server.address().port}`;
});

after(async () => {
  await new Promise((resolve) => server.close(resolve));
  db.close();
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test("flags, segments, rules, percentage rollout, kill switch, audit history, and live TypeScript SDK", async () => {
  const adm = await fetch(`${baseUrl}/api/auth/register`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ username: "fdadmin", password: "strongpassword1" }),
  }).then((r) => r.json());
  const hdr = { Authorization: `Bearer ${adm.token}`, "Content-Type": "application/json" };

  // Create project + environments
  const projRes = await fetch(`${baseUrl}/api/projects`, {
    method: "POST",
    headers: hdr,
    body: JSON.stringify({ key: "webapp", name: "Web Application" }),
  }).then((r) => r.json());
  const projectId = projRes.project.id;
  const prodEnv = projRes.environments.find((e) => e.key === "production");
  assert.ok(prodEnv.sdk_key.startsWith("fd_sdk_"));

  // Create reusable segment
  await fetch(`${baseUrl}/api/projects/${projectId}/segments`, {
    method: "POST",
    headers: hdr,
    body: JSON.stringify({
      name: "beta-testers",
      rules: [{ attribute: "plan", operator: "eq", value: "pro", serveValue: true }],
    }),
  });

  // Create boolean + JSON flags
  const dashFlag = await fetch(`${baseUrl}/api/projects/${projectId}/flags`, {
    method: "POST",
    headers: hdr,
    body: JSON.stringify({
      key: "new-dashboard",
      name: "New Dashboard",
      flag_type: "boolean",
      default_value: false,
      rollout_value: true,
    }),
  }).then((r) => r.json());

  const themeFlag = await fetch(`${baseUrl}/api/projects/${projectId}/flags`, {
    method: "POST",
    headers: hdr,
    body: JSON.stringify({
      key: "theme-config",
      name: "Theme JSON",
      flag_type: "json",
      default_value: { theme: "light" },
      rollout_value: { theme: "dark" },
    }),
  }).then((r) => r.json());

  // Enable new-dashboard with 100% rollout + user target & rule
  await fetch(`${baseUrl}/api/flags/${dashFlag.id}/environments/${prodEnv.id}`, {
    method: "PATCH",
    headers: hdr,
    body: JSON.stringify({
      enabled: true,
      rollout_percent: 100,
      user_targets: { "blocked-user": false },
      rules: [{ attribute: "", operator: "segment", value: "beta-testers", serveValue: true }],
    }),
  });

  // Enable theme-config via group target
  await fetch(`${baseUrl}/api/flags/${themeFlag.id}/environments/${prodEnv.id}`, {
    method: "PATCH",
    headers: hdr,
    body: JSON.stringify({
      enabled: true,
      rollout_percent: 0,
      group_targets: { enterprise: { theme: "contrast-dark" } },
    }),
  });

  // Exercise exact TypeScript SDK example usage against live HTTP API
  const client = new FeatureDock({
    apiUrl: baseUrl,
    sdkKey: prodEnv.sdk_key,
    cacheTtlMs: 0,
  });

  const enabled = await client.isEnabled("new-dashboard", { userId: "user-123" });
  assert.equal(enabled, true);
  assert.equal(await client.isEnabled("new-dashboard", { userId: "blocked-user" }), false);

  const theme = await client.getVariation("theme-config", { userId: "u1", groupId: "enterprise" });
  assert.deepEqual(theme, { theme: "contrast-dark" });

  // Trigger emergency kill switch -> immediately disables new-dashboard even for targeted users
  await fetch(`${baseUrl}/api/flags/${dashFlag.id}/environments/${prodEnv.id}`, {
    method: "PATCH",
    headers: hdr,
    body: JSON.stringify({ kill_switched: true }),
  });
  assert.equal(await client.isEnabled("new-dashboard", { userId: "user-123" }), false);

  // Verify audit logs and telemetry history were persisted
  const audit = await fetch(`${baseUrl}/api/projects/${projectId}/audit`, { headers: hdr }).then((r) => r.json());
  assert.ok(audit.audit.some((a) => a.action === "flag.update"));

  const evals = await fetch(`${baseUrl}/api/evaluations?env_id=${prodEnv.id}`, { headers: hdr }).then((r) => r.json());
  assert.ok(evals.evaluations.length >= 3);
});
