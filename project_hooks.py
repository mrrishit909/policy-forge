"""Policy Forge hooks for the generic harness (compute, feasibility, validation, headline, memory)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from harness.core import config
from harness.state import read_json

PUBLIC_FILES = [
    "manifest.json", "inventory.json", "relationships.json", "coverage.json", "findings.json", "exceptions.json",
    "conftest.json", "rule_tests.json", "remediation.json", "remediation.patch", "catalog.json", "summary.json",
    "report.md", "checks.json",
]


def compute(params: dict[str, Any], out_dir: Path) -> None:
    """Deterministic policy run (called by `python -m harness compute` on the read-only compute job)."""
    with tempfile.TemporaryDirectory() as tmp:
        req = Path(tmp) / "request.json"
        req.write_text(json.dumps(params))
        subprocess.run([sys.executable, "-m", "policyforge", "run", "--request", str(req), "--out", str(out_dir)],
                       check=True)


def request_problems(params: dict[str, Any]) -> list[str]:
    from policyforge.pipeline import request_problems as engine_problems

    return list(engine_problems(params))


def validate_outputs(out_dir: Path) -> list[str]:
    from policyforge.outputs import validate

    return validate(out_dir)


def headline(out_dir: Path) -> str | None:
    s = json.loads((out_dir / "summary.json").read_text())
    checks, findings = s["checks"], s["findings"]
    return (f"{s['snapshot']} as of {s['as_of']}: {findings['active']} failed, {checks['unknown']} not evaluated, "
            f"{findings['excepted']} excepted, {checks['passed']} passed; "
            f"{'complete' if s['complete_coverage'] else 'partial'} coverage.")


def on_publish(root: Path, record: dict[str, Any], out_dir: Path) -> list[str]:
    return []


def memory_candidates(root: Path) -> list[dict[str, Any]]:
    """Lessons backed by at least three completed runs: recurring failed rules and recurring unevaluable checks."""
    cfg = config()
    index = read_json(root, "index.json", {"runs": []})
    failed: Counter[str] = Counter()
    failed_runs: dict[str, list[str]] = {}
    unknown: Counter[str] = Counter()
    unknown_runs: dict[str, list[str]] = {}
    for entry in index["runs"]:
        if entry["status"] != "completed":
            continue
        rid = entry["run_id"]
        findings = read_json(root, f"runs/{rid}/findings.json")
        coverage = read_json(root, f"runs/{rid}/coverage.json")
        if not findings or not coverage:
            continue
        for rule in sorted({f["rule_id"] for f in _list(findings, "findings")}):
            failed[rule] += 1
            failed_runs.setdefault(rule, []).append(rid)
        for rule in sorted({r["rule_id"] for r in _list(coverage, "results") if r.get("status") == "unknown"}):
            unknown[rule] += 1
            unknown_runs.setdefault(rule, []).append(rid)
    base = f"https://github.com/{cfg['owner']}/{cfg['repo']}/blob/{cfg['state_branch']}"
    expires = (date.today() + timedelta(days=90)).isoformat()
    out = []
    for rule, count in sorted(failed.items()):
        if count >= 3:
            runs = sorted(set(failed_runs[rule]))[:20]
            out.append({
                "topic": f"Rule {rule} fails repeatedly",
                "finding": f"Rule {rule} produced at least one failed check in {count} completed runs.",
                "supporting_run_ids": runs,
                "evidence_links": [f"{base}/runs/{r}/findings.json" for r in runs[:5]],
                "scope": "data-quality",
                "confidence": "medium" if count >= 6 else "low",
                "revalidate_when": "after a snapshot, rule or exception change",
                "expires_on": expires,
            })
    for rule, count in sorted(unknown.items()):
        if count >= 3:
            runs = sorted(set(unknown_runs[rule]))[:20]
            out.append({
                "topic": f"Rule {rule} often cannot be evaluated",
                "finding": f"Rule {rule} left at least one check unevaluated in {count} completed runs; "
                           "the configuration uses semantics the rule does not model.",
                "supporting_run_ids": runs,
                "evidence_links": [f"{base}/runs/{r}/coverage.json" for r in runs[:5]],
                "scope": "data-quality",
                "confidence": "medium" if count >= 6 else "low",
                "revalidate_when": "after the rule gains support for the unevaluated semantics",
                "expires_on": expires,
            })
    return out


def _list(doc: Any, key: str) -> list[dict[str, Any]]:
    """The list under `key`; an unrecognised shape is an error, never silently empty."""
    if isinstance(doc, list):
        return doc
    if isinstance(doc, dict) and isinstance(doc.get(key), list):
        return doc[key]
    raise ValueError(f"expected a list under {key!r}")
