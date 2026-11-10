"""Sandbox gateway: every agent action passes credential -> Cedar authz -> egress -> audit."""

from __future__ import annotations

import posixpath
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .audit import AuditLog
from .cedar import Authorizer, Entities, Request, UID, parse
from .credentials import Broker, CredentialError
from .egress import Allowlist

POLICY_FILE = Path(__file__).resolve().parents[2] / "policies" / "sandbox.cedar"


@dataclass
class Result:
    allowed: bool
    stage: str  # credential | resource | policy | egress | ok
    reason: str


class Sandbox:
    def __init__(
        self,
        broker: Broker,
        allowlist: Allowlist,
        audit: AuditLog,
        agents: list[str],
        secrets: dict[str, str] | None = None,
        host_categories: dict[str, str] | None = None,
        policy_src: str | None = None,
    ):
        self.broker, self.allow, self.audit = broker, allowlist, audit
        self.ents = Entities()
        self.ents.add(UID("Role", "agent"))
        for a in agents:
            self.ents.add(UID("Agent", a), {"name": a}, [UID("Role", "agent")])
        self.secrets = secrets or {}
        for name, task in self.secrets.items():
            self.ents.add(UID("Secret", name), {"task": task})
        self.host_categories = host_categories or {}
        self.authz = Authorizer(parse(policy_src or POLICY_FILE.read_text()), self.ents)

    def _resource(self, action: str, target: str) -> UID:
        if action in ("file_read", "file_write", "file_delete"):
            path = posixpath.normpath("/" + target.lstrip("/"))
            parts = path.split("/")
            task = parts[2] if len(parts) > 3 and parts[1] == "workspace" else ""
            u = UID("File", path)
            self.ents.add(u, {"path": path, "task": task})
            return u
        if action in ("http_get", "http_post"):
            host = (urlsplit(target).hostname or "").lower()
            u = UID("Host", host)
            attrs = {"name": host}
            if host in self.host_categories:
                attrs["category"] = self.host_categories[host]
            self.ents.add(u, attrs)
            return u
        if action == "secret_read":
            return UID("Secret", target)
        if action == "spawn_agent":
            return UID("Agent", target)
        return UID("Policy", target)

    def request(
        self,
        agent: str,
        token: str,
        action: str,
        target: str,
        now: float,
        child_scopes: list[str] | None = None,
    ) -> Result:
        res = self._decide(agent, token, action, target, now, child_scopes)
        self.audit.append(
            {
                "t": now,
                "agent": agent,
                "action": action,
                "target": target,
                "allowed": res.allowed,
                "stage": res.stage,
                "reason": res.reason,
            }
        )
        return res

    def _decide(self, agent, token, action, target, now, child_scopes) -> Result:
        try:
            claims = self.broker.verify(token, agent, now)
        except CredentialError as e:
            return Result(False, "credential", e.code)
        ctx = {
            "task": claims["task"],
            "scopes": claims["scopes"],
            "child_scopes_subset": set(child_scopes or []) <= set(claims["scopes"]),
        }
        res = self._resource(action, target)
        ans = self.authz.is_authorized(
            Request(UID("Agent", agent), UID("Action", action), res, ctx)
        )
        if ans.decision != "Allow":
            return Result(False, "policy", ",".join(ans.reasons) or "no_permit")
        if action in ("http_get", "http_post"):
            ok, why = self.allow.check(target)
            if not ok:
                return Result(False, "egress", why)
        return Result(True, "ok", ",".join(ans.reasons))
