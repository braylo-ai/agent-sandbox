"""Egress allowlist: a URL checker plus a real HTTP forward proxy that enforces it.

Allowlist entries are origins: "https://api.github.com", "http://127.0.0.1:8080",
or wildcard subdomains "https://*.s3.example". Matching is on (scheme, host, port)
after normalisation. Blocked: userinfo tricks, IP literals not listed, non-ASCII
hosts, other schemes, other ports.
"""

from __future__ import annotations

import http.client
import ipaddress
import select
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

DEFAULT_PORT = {"http": 80, "https": 443}


def _parse_entry(e: str) -> tuple[str, str, int]:
    p = urlsplit(e)
    host = p.netloc.rsplit(":", 1)[0] if p.port else p.netloc
    return p.scheme, host.lower(), p.port or DEFAULT_PORT[p.scheme]


class Allowlist:
    def __init__(self, entries: list[str]):
        self.entries = [_parse_entry(e) for e in entries]

    def check(self, url: str) -> tuple[bool, str]:
        try:
            p = urlsplit(url)
            port = p.port
        except ValueError:
            return False, "unparseable"
        if p.scheme not in DEFAULT_PORT:
            return False, "scheme_not_allowed"
        if "@" in p.netloc:
            return False, "userinfo_in_url"
        host = (p.hostname or "").rstrip(".")
        if not host:
            return False, "no_host"
        if not host.isascii():
            return False, "non_ascii_host"
        port = port or DEFAULT_PORT[p.scheme]
        is_ip = _is_ip(host)
        for scheme, h, prt in self.entries:
            if scheme != p.scheme or prt != port:
                continue
            if h == host:
                return True, "allowlisted"
            if (
                h.startswith("*.")
                and not is_ip
                and host.endswith(h[1:])
                and host != h[2:]
            ):
                return True, "allowlisted_wildcard"
        if is_ip:
            return False, "ip_literal_not_allowlisted"
        return False, "host_not_allowlisted"


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h.strip("[]"))
        return True
    except ValueError:
        # decimal / hex integer encodings like 2130706433 or 0x7f000001
        return h.isdigit() or h.lower().startswith("0x")


def make_proxy(allow: Allowlist, log: list) -> ThreadingHTTPServer:
    """A forward proxy on 127.0.0.1 (random port). Denied requests never resolve DNS."""

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):  # quiet
            pass

        def _deny(self, reason):
            log.append(("deny", self.command, self.path, reason))
            self.send_response(403)
            self.send_header("X-Egress-Deny", reason)
            self.end_headers()

        def do_GET(self):
            ok, reason = allow.check(self.path)
            if not ok:
                return self._deny(reason)
            p = urlsplit(self.path)
            log.append(("allow", "GET", self.path, reason))
            conn = http.client.HTTPConnection(p.hostname, p.port or 80, timeout=5)
            conn.request("GET", p.path or "/")
            r = conn.getresponse()
            data = r.read()
            self.send_response(r.status)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_POST = do_GET

        def do_CONNECT(self):
            ok, reason = allow.check(f"https://{self.path}")
            if not ok:
                return self._deny(reason)
            host, port = self.path.rsplit(":", 1)
            log.append(("allow", "CONNECT", self.path, reason))
            up = socket.create_connection((host, int(port)), timeout=5)
            self.send_response(200)
            self.end_headers()
            socks = [self.connection, up]
            while True:
                r, _, _ = select.select(socks, [], [], 5)
                if not r:
                    break
                for s in r:
                    data = s.recv(65536)
                    if not data:
                        up.close()
                        return
                    (up if s is self.connection else self.connection).sendall(data)

    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv
