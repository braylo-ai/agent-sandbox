"""Append-only, hash-chained audit log (JSON Lines).

The API has append and verify only. Each entry stores the SHA-256 of the
previous entry, so editing, deleting or reordering any line breaks verify().
The file is opened in append mode for writes; nothing rewrites it.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

GENESIS = "0" * 64


def _h(prev: str, rec: dict) -> str:
    return hashlib.sha256((prev + json.dumps(rec, sort_keys=True)).encode()).hexdigest()


class AuditLog:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.path.touch(exist_ok=True)
        self.head = GENESIS
        for line in self.path.read_text().splitlines():
            self.head = json.loads(line)["hash"]

    def append(self, rec: dict) -> str:
        h = _h(self.head, rec)
        with self.path.open("a") as f:
            f.write(
                json.dumps({"prev": self.head, "rec": rec, "hash": h}, sort_keys=True)
                + "\n"
            )
        self.head = h
        return h

    def verify(self) -> tuple[bool, int | None]:
        """Return (ok, first_bad_line_index)."""
        prev = GENESIS
        for i, line in enumerate(self.path.read_text().splitlines()):
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                return False, i
            if e["prev"] != prev or _h(prev, e["rec"]) != e["hash"]:
                return False, i
            prev = e["hash"]
        return True, None

    def entries(self) -> list[dict]:
        return [json.loads(x)["rec"] for x in self.path.read_text().splitlines()]
