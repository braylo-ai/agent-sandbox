import threading
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from sandbox.attempts import ATTEMPTS, run_all
from sandbox.audit import AuditLog
from sandbox.cedar import Authorizer, CedarError, Entities, Request, UID, parse
from sandbox.credentials import Broker, CredentialError
from sandbox.egress import Allowlist, make_proxy


# ---- Cedar subset ----


def _authz(src, ents=None):
    return Authorizer(parse(src), ents or Entities())


def _req(ctx=None, action="read"):
    return Request(
        UID("Agent", "a"), UID("Action", action), UID("File", "f"), ctx or {}
    )


def test_cedar_default_deny():
    assert _authz("").is_authorized(_req()).decision == "Deny"


def test_cedar_permit_with_when():
    a = _authz(
        'permit (principal, action == Action::"read", resource) when { context.ok == true };'
    )
    assert a.is_authorized(_req({"ok": True})).decision == "Allow"
    assert a.is_authorized(_req({"ok": False})).decision == "Deny"


def test_cedar_forbid_overrides_permit():
    a = _authz(
        'permit (principal, action, resource); forbid (principal, action == Action::"read", resource);'
    )
    ans = a.is_authorized(_req())
    assert ans.decision == "Deny" and ans.reasons == ["policy1"]


def test_cedar_unless_and_contains():
    a = _authz(
        'permit (principal, action, resource) unless { context.scopes.contains("banned") };'
    )
    assert a.is_authorized(_req({"scopes": ["x"]})).decision == "Allow"
    assert a.is_authorized(_req({"scopes": ["banned"]})).decision == "Deny"


def test_cedar_hierarchy_in():
    e = Entities()
    e.add(UID("Role", "agent"))
    e.add(UID("Agent", "a"), parents=[UID("Role", "agent")])
    a = _authz('permit (principal in Role::"agent", action, resource);', e)
    assert a.is_authorized(_req()).decision == "Allow"
    other = Request(UID("Agent", "z"), UID("Action", "read"), UID("File", "f"), {})
    assert a.is_authorized(other).decision == "Deny"


def test_cedar_like_is_literal_except_star():
    e = Entities()
    e.add(UID("File", "f"), {"path": "/w/t1/a?b"})
    a = _authz(
        'permit (principal, action, resource) when { resource.path like "/w/*/a?b" };',
        e,
    )
    assert a.is_authorized(_req()).decision == "Allow"
    e.add(UID("File", "f"), {"path": "/w/t1/axb"})
    assert a.is_authorized(_req()).decision == "Deny"


def test_cedar_error_skips_policy():
    a = _authz("permit (principal, action, resource) when { context.missing == 1 };")
    ans = a.is_authorized(_req({}))
    assert ans.decision == "Deny" and ans.errors


def test_cedar_parse_error():
    with pytest.raises(CedarError):
        parse("allow (principal, action, resource);")


# ---- credentials ----


def test_token_roundtrip_and_expiry():
    b = Broker()
    t = b.issue("a", "t", ["fs:read"], now=0, ttl=10)
    assert b.verify(t, "a", now=5)["task"] == "t"
    with pytest.raises(CredentialError, match="expired"):
        b.verify(t, "a", now=11)


def test_ttl_is_capped():
    b = Broker(max_ttl=900)
    t = b.issue("a", "t", [], now=0, ttl=10**6)
    with pytest.raises(CredentialError):
        b.verify(t, "a", now=901)


def test_delegation_cannot_escalate_or_outlive_parent():
    b = Broker()
    p = b.issue("a", "t", ["fs:read", "fs:write"], now=0, ttl=100)
    with pytest.raises(CredentialError, match="scope_escalation"):
        b.delegate(p, "a", "child", ["admin"], now=1)
    c = b.delegate(p, "a", "child", ["fs:read"], now=50, ttl=1000)
    with pytest.raises(CredentialError, match="expired"):
        b.verify(c, "child", now=101)


def test_end_task_revokes():
    b = Broker()
    t = b.issue("a", "t", [], now=0)
    b.end_task("t")
    with pytest.raises(CredentialError, match="revoked"):
        b.verify(t, "a", now=1)


# ---- egress ----

AL = Allowlist(["https://api.github.com", "https://*.s3.example", "http://127.0.0.1:9"])


@pytest.mark.parametrize(
    "url,ok",
    [
        ("https://api.github.com/x", True),
        ("https://API.GITHUB.COM./x", True),
        ("https://b.s3.example/x", True),
        ("https://s3.example/x", False),
        ("https://api.github.com.evil.example/", False),
        ("https://api.github.com@evil.example/", False),
        ("http://api.github.com/", False),
        ("https://api.github.com:444/", False),
        ("http://127.0.0.1:9/", True),
        ("http://127.0.0.2:9/", False),
        ("http://0x7f000001/", False),
    ],
)
def test_allowlist(url, ok):
    assert AL.check(url)[0] is ok


class _Up(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"upstream-ok")


def test_real_proxy_allows_listed_and_blocks_unlisted():
    up = ThreadingHTTPServer(("127.0.0.1", 0), _Up)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    port = up.server_address[1]
    log: list = []
    px = make_proxy(Allowlist([f"http://127.0.0.1:{port}"]), log)
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(
            {"http": f"http://127.0.0.1:{px.server_address[1]}"}
        )
    )
    try:
        assert (
            opener.open(f"http://127.0.0.1:{port}/x", timeout=5).read()
            == b"upstream-ok"
        )
        with pytest.raises(urllib.error.HTTPError) as e:
            opener.open("http://exfil.invalid/steal", timeout=5)
        assert (
            e.value.code == 403
            and e.value.headers["X-Egress-Deny"] == "host_not_allowlisted"
        )
        assert [x[0] for x in log] == ["allow", "deny"]
    finally:
        px.shutdown()
        up.shutdown()


# ---- audit ----


def test_audit_chain_detects_edit(tmp_path):
    log = AuditLog(tmp_path / "a.jsonl")
    for i in range(5):
        log.append({"i": i, "allowed": False})
    assert log.verify() == (True, None)
    lines = (tmp_path / "a.jsonl").read_text().splitlines()
    lines[2] = lines[2].replace('"allowed": false', '"allowed": true')
    (tmp_path / "a.jsonl").write_text("\n".join(lines) + "\n")
    assert log.verify() == (False, 2)


def test_audit_reload_continues_chain(tmp_path):
    p = tmp_path / "a.jsonl"
    AuditLog(p).append({"x": 1})
    l2 = AuditLog(p)
    l2.append({"x": 2})
    assert l2.verify()[0] and len(l2.entries()) == 2


# ---- full suite ----


def test_suite_size():
    assert sum(not a[-1] for a in ATTEMPTS) >= 30


def test_suite_outcomes_and_audit():
    r = run_all()
    wrong = [x["id"] for x in r["rows"] if not x["correct"]]
    assert wrong == ["gap-exfil-allowlisted-query"]  # the one documented gap
    assert r["audit_entries"] == len(ATTEMPTS) and r["audit_chain_valid"]
    assert all(r["tamper_detected"].values())
