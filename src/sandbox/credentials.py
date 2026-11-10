"""Scoped, short-lived credentials bound to one agent and one task.

Tokens are HMAC-SHA256 signed claims (JWT-like, stdlib only). The signing key
is generated at runtime and never written to disk.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


class CredentialError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


@dataclass
class Broker:
    default_ttl: float = 300.0
    max_ttl: float = 900.0
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    revoked_tasks: set = field(default_factory=set)
    revoked_jti: set = field(default_factory=set)
    used_jti: set = field(default_factory=set)

    def issue(
        self,
        agent: str,
        task: str,
        scopes: list[str],
        now: float,
        ttl: float | None = None,
        one_time: bool = False,
        aud: str = "sandbox",
    ) -> str:
        ttl = min(ttl or self.default_ttl, self.max_ttl)
        claims = {
            "sub": agent,
            "task": task,
            "scopes": sorted(set(scopes)),
            "aud": aud,
            "iat": now,
            "exp": now + ttl,
            "jti": secrets.token_hex(8),
            "one_time": one_time,
        }
        body = _b64(json.dumps(claims, sort_keys=True).encode())
        sig = _b64(hmac.new(self.key, body.encode(), hashlib.sha256).digest())
        return f"{body}.{sig}"

    def verify(self, token: str, agent: str, now: float, aud: str = "sandbox") -> dict:
        try:
            body, sig = token.split(".")
        except ValueError:
            raise CredentialError("malformed")
        good = _b64(hmac.new(self.key, body.encode(), hashlib.sha256).digest())
        if not hmac.compare_digest(good, sig):
            raise CredentialError("bad_signature")
        c = json.loads(_unb64(body))
        if c["aud"] != aud:
            raise CredentialError("wrong_audience")
        if now >= c["exp"]:
            raise CredentialError("expired")
        if now < c["iat"] - 5:
            raise CredentialError("not_yet_valid")
        if c["sub"] != agent:
            raise CredentialError("wrong_agent")
        if c["task"] in self.revoked_tasks or c["jti"] in self.revoked_jti:
            raise CredentialError("revoked")
        if c["one_time"]:
            if c["jti"] in self.used_jti:
                raise CredentialError("replayed")
            self.used_jti.add(c["jti"])
        return c

    def end_task(self, task: str) -> None:
        """Revoke every credential for a task when the task finishes."""
        self.revoked_tasks.add(task)

    def delegate(
        self,
        parent_token: str,
        agent: str,
        child_agent: str,
        scopes: list[str],
        now: float,
        ttl: float | None = None,
    ) -> str:
        """Mint a child credential. Scopes must be a subset; expiry cannot outlive the parent."""
        c = self.verify(parent_token, agent, now)
        if not set(scopes) <= set(c["scopes"]):
            raise CredentialError("scope_escalation")
        remaining = c["exp"] - now
        return self.issue(
            child_agent, c["task"], scopes, now, min(ttl or remaining, remaining)
        )
