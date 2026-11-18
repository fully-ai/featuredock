"""Official Python SDK for FeatureDock."""

from __future__ import annotations

import hashlib
import json
import struct
import time
import urllib.request
from typing import Any


class FeatureDockClient:
    def __init__(self, api_url: str, sdk_key: str, cache_ttl_sec: float = 15.0) -> None:
        self.api_url = api_url.rstrip("/")
        self.sdk_key = sdk_key
        self.cache_ttl_sec = cache_ttl_sec
        self._etag = ""
        self._last_fetch = 0.0
        self._flags: dict[str, dict[str, Any]] = {}

    def _refresh_snapshot(self) -> None:
        if time.monotonic() - self._last_fetch < self.cache_ttl_sec and self._flags:
            return
        headers = {"Authorization": f"Bearer {self.sdk_key}"}
        if self._etag:
            headers["If-None-Match"] = self._etag
        req = urllib.request.Request(f"{self.api_url}/api/sdk/v1/snapshot", headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=5.0) as resp:
                self._etag = resp.headers.get("ETag", "")
                data = json.loads(resp.read().decode("utf-8"))
                self._flags = data.get("flags", {})
                self._last_fetch = time.monotonic()
        except urllib.error.HTTPError as exc:
            if exc.code == 304:
                self._last_fetch = time.monotonic()
                return
            raise

    def _eval_local(self, cfg: dict[str, Any], ctx: dict[str, Any]) -> Any:
        if cfg.get("killSwitched"):
            return cfg.get("defaultValue")
        if not cfg.get("enabled"):
            return cfg.get("defaultValue")
        uid = ctx.get("userId")
        if uid and uid in cfg.get("userTargets", {}):
            return cfg["userTargets"][uid]
        for g in ([ctx.get("groupId")] if ctx.get("groupId") else []) + list(ctx.get("groups") or []):
            if g in cfg.get("groupTargets", {}):
                return cfg["groupTargets"][g]
        pct = float(cfg.get("rolloutPercent", 0))
        if pct >= 100:
            return cfg.get("rolloutValue")
        if pct > 0 and uid:
            digest = hashlib.sha256(f"{cfg['salt']}:{cfg['flagKey']}:{uid}".encode()).digest()
            bucket = struct.unpack(">I", digest[:4])[0] % 10000
            if bucket < round(pct * 100):
                return cfg.get("rolloutValue")
        return cfg.get("defaultValue")

    def get_variation(self, flag_key: str, context: dict[str, Any] | None = None, default: Any = None) -> Any:
        self._refresh_snapshot()
        cfg = self._flags.get(flag_key)
        if cfg is None:
            return default
        return self._eval_local(cfg, context or {})

    def is_enabled(self, flag_key: str, context: dict[str, Any] | None = None, default: bool = False) -> bool:
        return bool(self.get_variation(flag_key, context, default))
