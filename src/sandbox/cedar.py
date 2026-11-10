"""A small interpreter for a SUBSET of the Cedar policy language.

This is not the official cedar-policy engine. It parses policies written in
Cedar syntax and follows Cedar's decision rule: any matching `forbid` wins,
otherwise any matching `permit` allows, otherwise deny (default deny). A policy
whose condition raises an evaluation error is skipped, as in Cedar.

Supported:
  permit|forbid ( principal [== E | in E | is T], action [== E | in [E,..]],
                  resource [== E | in E | is T] ) [when {..}] [unless {..}] ;
  expressions: || && ! == != < <= > >= in like has .attr .contains(x)
               string / int / bool literals, [lists], Type::"id" entity refs,
               principal action resource context, parentheses, // comments
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

TOKEN = re.compile(
    r'\s*(?://[^\n]*\n?|(?P<s>"(?:[^"\\]|\\.)*")|(?P<n>-?\d+)|(?P<op>==|!=|<=|>=|&&|\|\||::|[(){}\[\],;.!<>])|(?P<id>[A-Za-z_][A-Za-z0-9_]*))'
)


class CedarError(Exception):
    pass


@dataclass(frozen=True)
class UID:
    type: str
    id: str

    def __str__(self):
        return f'{self.type}::"{self.id}"'


def uid(s: str) -> UID:
    t, i = s.split("::", 1)
    return UID(t, i.strip('"'))


@dataclass
class Policy:
    effect: str
    scope: dict
    conds: list  # [(kind, ast)]
    text: str = ""
    pid: str = ""


def tokenize(src: str) -> list[tuple[str, str]]:
    out, pos = [], 0
    while pos < len(src):
        m = TOKEN.match(src, pos)
        if not m or m.end() == pos:
            if src[pos:].strip() == "":
                break
            raise CedarError(f"bad token at {pos}: {src[pos:pos+20]!r}")
        pos = m.end()
        for k in ("s", "n", "op", "id"):
            if m.group(k) is not None:
                out.append((k, m.group(k)))
    return out


class Parser:
    def __init__(self, toks):
        self.t, self.i = toks, 0

    def peek(self, k=0):
        return self.t[self.i + k][1] if self.i + k < len(self.t) else None

    def eat(self, v=None):
        tok = self.t[self.i]
        if v is not None and tok[1] != v:
            raise CedarError(f"expected {v!r} got {tok[1]!r}")
        self.i += 1
        return tok

    def policies(self) -> list[Policy]:
        out = []
        while self.i < len(self.t):
            out.append(self.policy(len(out)))
        return out

    def policy(self, n) -> Policy:
        eff = self.eat()[1]
        if eff not in ("permit", "forbid"):
            raise CedarError(f"expected permit/forbid, got {eff}")
        self.eat("(")
        scope = {}
        for var in ("principal", "action", "resource"):
            self.eat(var)
            scope[var] = self.scope_constraint(var)
            if var != "resource":
                self.eat(",")
        self.eat(")")
        conds = []
        while self.peek() in ("when", "unless"):
            kind = self.eat()[1]
            self.eat("{")
            conds.append((kind, self.expr()))
            self.eat("}")
        self.eat(";")
        return Policy(eff, scope, conds, pid=f"policy{n}")

    def scope_constraint(self, var):
        p = self.peek()
        if p == "==":
            self.eat()
            return ("eq", self.entity())
        if p == "in":
            self.eat()
            if self.peek() == "[":
                return ("in_list", self.list_lit())
            return ("in", self.entity())
        if p == "is":
            self.eat()
            return ("is", self.eat()[1])
        return ("any",)

    def entity(self) -> UID:
        parts = [self.eat()[1]]
        while self.peek() == "::":
            self.eat()
            tok = self.eat()
            if tok[0] == "s":
                return UID("::".join(parts), tok[1][1:-1])
            parts.append(tok[1])
        raise CedarError("bad entity ref")

    def list_lit(self):
        self.eat("[")
        items = []
        while self.peek() != "]":
            items.append(self.expr())
            if self.peek() == ",":
                self.eat()
        self.eat("]")
        return ("list", items)

    # expressions
    def expr(self):
        left = self.and_()
        while self.peek() == "||":
            self.eat()
            left = ("or", left, self.and_())
        return left

    def and_(self):
        left = self.unary()
        while self.peek() == "&&":
            self.eat()
            left = ("and", left, self.unary())
        return left

    def unary(self):
        if self.peek() == "!":
            self.eat()
            return ("not", self.unary())
        return self.cmp()

    def cmp(self):
        left = self.member()
        p = self.peek()
        if p in ("==", "!=", "<", "<=", ">", ">=", "in", "like"):
            self.eat()
            return ("cmp", p, left, self.member())
        if p == "has":
            self.eat()
            return ("has", left, self.eat()[1])
        return left

    def member(self):
        node = self.primary()
        while self.peek() == ".":
            self.eat()
            name = self.eat()[1]
            if name == "contains" and self.peek() == "(":
                self.eat("(")
                arg = self.expr()
                self.eat(")")
                node = ("contains", node, arg)
            else:
                node = ("attr", node, name)
        return node

    def primary(self):
        kind, v = self.t[self.i]
        if v == "(":
            self.eat()
            e = self.expr()
            self.eat(")")
            return e
        if v == "[":
            return self.list_lit()
        if kind == "s":
            self.eat()
            return ("lit", bytes(v[1:-1], "utf-8").decode("unicode_escape"))
        if kind == "n":
            self.eat()
            return ("lit", int(v))
        if v in ("true", "false"):
            self.eat()
            return ("lit", v == "true")
        if v in ("principal", "action", "resource", "context"):
            self.eat()
            return ("var", v)
        if kind == "id" and self.peek(1) == "::":
            return ("lit", self.entity())
        raise CedarError(f"unexpected {v!r}")


def parse(src: str) -> list[Policy]:
    return Parser(tokenize(src)).policies()


@dataclass
class Entities:
    store: dict = field(default_factory=dict)  # UID -> {"attrs": {}, "parents": [UID]}

    def add(self, u: UID, attrs: dict | None = None, parents: list | None = None):
        self.store[u] = {"attrs": attrs or {}, "parents": parents or []}

    def ancestors(self, u: UID) -> set:
        seen, stack = set(), list(self.store.get(u, {}).get("parents", []))
        while stack:
            p = stack.pop()
            if p not in seen:
                seen.add(p)
                stack.extend(self.store.get(p, {}).get("parents", []))
        return seen

    def is_in(self, u: UID, target: UID) -> bool:
        return u == target or target in self.ancestors(u)


@dataclass
class Request:
    principal: UID
    action: UID
    resource: UID
    context: dict


@dataclass
class Answer:
    decision: str  # "Allow" | "Deny"
    reasons: list  # policy ids that determined the decision
    errors: list


class Authorizer:
    def __init__(self, policies: list[Policy], entities: Entities):
        self.policies, self.ents = policies, entities

    def _scope_ok(self, p: Policy, req: Request) -> bool:
        for var in ("principal", "action", "resource"):
            c = p.scope[var]
            val = getattr(req, var)
            if c[0] == "eq" and val != c[1]:
                return False
            if c[0] == "in" and not self.ents.is_in(val, c[1]):
                return False
            if c[0] == "is" and val.type != c[1]:
                return False
            if c[0] == "in_list" and not any(
                self.ents.is_in(val, self.ev(x, req)) for x in c[1][1]
            ):
                return False
        return True

    def ev(self, n, req: Request):
        k = n[0]
        if k == "lit":
            return n[1]
        if k == "var":
            return req.context if n[1] == "context" else getattr(req, n[1])
        if k == "list":
            return [self.ev(x, req) for x in n[1]]
        if k == "or":
            return self._bool(self.ev(n[1], req)) or self._bool(self.ev(n[2], req))
        if k == "and":
            return self._bool(self.ev(n[1], req)) and self._bool(self.ev(n[2], req))
        if k == "not":
            return not self._bool(self.ev(n[1], req))
        if k == "attr":
            obj = self.ev(n[1], req)
            attrs = (
                self.ents.store.get(obj, {}).get("attrs")
                if isinstance(obj, UID)
                else obj
            )
            if not isinstance(attrs, dict) or n[2] not in attrs:
                raise CedarError(f"missing attribute {n[2]}")
            return attrs[n[2]]
        if k == "has":
            obj = self.ev(n[1], req)
            attrs = (
                self.ents.store.get(obj, {}).get("attrs")
                if isinstance(obj, UID)
                else obj
            )
            return isinstance(attrs, dict) and n[2] in attrs
        if k == "contains":
            coll = self.ev(n[1], req)
            if not isinstance(coll, (list, set, tuple)):
                raise CedarError("contains on non-set")
            return self.ev(n[2], req) in coll
        if k == "cmp":
            op, a, b = n[1], self.ev(n[2], req), self.ev(n[3], req)
            if op == "==":
                return a == b
            if op == "!=":
                return a != b
            if op == "in":
                if isinstance(b, list):
                    return any(isinstance(a, UID) and self.ents.is_in(a, x) for x in b)
                return isinstance(a, UID) and self.ents.is_in(a, b)
            if op == "like":
                if not isinstance(a, str):
                    raise CedarError("like on non-string")
                return re.fullmatch(".*".join(re.escape(x) for x in b.split("*")), a, re.S) is not None
            if not (isinstance(a, int) and isinstance(b, int)) or isinstance(a, bool):
                raise CedarError("ordering on non-int")
            return {"<": a < b, "<=": a <= b, ">": a > b, ">=": a >= b}[op]
        raise CedarError(f"bad node {k}")

    @staticmethod
    def _bool(v):
        if not isinstance(v, bool):
            raise CedarError("non-boolean in boolean context")
        return v

    def is_authorized(self, req: Request) -> Answer:
        permits, forbids, errors = [], [], []
        for p in self.policies:
            if not self._scope_ok(p, req):
                continue
            try:
                ok = True
                for kind, ast in p.conds:
                    v = self._bool(self.ev(ast, req))
                    ok = ok and (v if kind == "when" else not v)
                    if not ok:
                        break
            except CedarError as e:
                errors.append(f"{p.pid}: {e}")
                continue
            if ok:
                (forbids if p.effect == "forbid" else permits).append(p.pid)
        if forbids:
            return Answer("Deny", forbids, errors)
        if permits:
            return Answer("Allow", permits, errors)
        return Answer("Deny", [], errors)
