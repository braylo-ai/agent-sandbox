"""Run the escape/escalation suite and write results/results.json.

    python evals/run_eval.py
"""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sandbox.attempts import run_all  # noqa: E402


def main() -> None:
    r = run_all()
    cat = defaultdict(lambda: {"n": 0, "correct": 0, "allowed": 0})
    stage = defaultdict(int)
    for row in r["rows"]:
        c = cat[row["category"]]
        c["n"] += 1
        c["correct"] += row["correct"]
        c["allowed"] += row["allowed"]
        if not row["allowed"]:
            stage[row["stage"]] += 1
    attacks = [x for x in r["rows"] if not x["expected_allowed"]]
    legit = [x for x in r["rows"] if x["expected_allowed"]]
    r["summary"] = {
        "n_attempts": len(attacks), "attacks_blocked": sum(not x["allowed"] for x in attacks),
        "n_legit": len(legit), "legit_allowed": sum(x["allowed"] for x in legit),
        "per_category": dict(cat), "blocked_by_stage": dict(stage),
    }
    (ROOT / "results" / "results.json").write_text(json.dumps(r, indent=2, ensure_ascii=False))
    print(json.dumps(r["summary"], indent=1))
    print("audit entries:", r["audit_entries"], "chain valid:", r["audit_chain_valid"], "tamper detected:", r["tamper_detected"])
    for x in r["rows"]:
        if not x["correct"]:
            print("WRONG:", x)


if __name__ == "__main__":
    main()
