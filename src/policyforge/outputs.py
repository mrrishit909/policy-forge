"""Run outputs: deterministic JSON (sorted keys, stable order, no wall-clock time), report.md, self-checks, and
`validate(out_dir)` which re-checks a finished run directory from its files alone."""

from __future__ import annotations

import hashlib
import json
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from policyforge import __version__, redact

ROOT = Path(__file__).resolve().parents[2]
JSON_FILES = ["manifest.json", "inventory.json", "relationships.json", "coverage.json", "findings.json",
              "exceptions.json", "conftest.json", "rule_tests.json", "remediation.json", "catalog.json",
              "summary.json", "checks.json"]
REQUIRED = JSON_FILES + ["report.md"]
BANNED = re.compile(r"(?i)compliant|compliance achieved")
MAX_BYTES = 2_000_000
STATUSES = ("pass", "fail", "unknown")


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


@dataclass
class Bundle:
    params: dict[str, Any]
    manifest: dict[str, Any]
    context: dict[str, Any]
    provider: str
    catalog: dict[str, Any]
    pack_rules: list[dict[str, Any]]
    rules: list[dict[str, Any]]
    ev: Any
    results: list[dict[str, Any]]
    findings: list[dict[str, Any]]
    exceptions: list[dict[str, Any]]
    exc_hygiene: dict[str, Any]
    remediation: dict[str, Any]
    rule_tests: dict[str, Any]
    versions: dict[str, str | None]
    hashes: list[dict[str, Any]]
    input_hash: str
    launched: list[str]
    snapshot_unchanged: bool
    coverage_unknown: list[dict[str, Any]]


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def coverage(b: Bundle) -> dict[str, Any]:
    inv = b.ev.inventory
    rule_types: dict[str, list[str]] = {}
    for r in b.rules:
        for t in r["resource_types"]:
            rule_types.setdefault(t, []).append(r["id"])
    per_res: dict[str, list[str]] = {}
    for r in b.results:
        per_res.setdefault(r["resource_id"], []).append(r["status"])
    unknown_src = {(u["rule_id"], u["resource_id"]): u for u in b.coverage_unknown}
    by_id = {r["id"]: r for r in inv}

    results = []
    for r in b.results:
        row = {"rule_id": r["rule_id"], "resource_id": r["resource_id"],
               "resource_type": by_id[r["resource_id"]]["type"], "status": r["status"], "reason": r["reason"],
               "evidence": r["evidence"]}
        if r["status"] == "unknown":
            u = unknown_src[(r["rule_id"], r["resource_id"])]
            row.update(source=u["source"], cited=u["cited"])
        results.append(row)

    resources, unsupported = [], []
    from policyforge.pipeline import cite

    for r in inv:
        statuses = per_res.get(r["id"], [])
        if r["type"] == "unsupported":
            status, note = "unknown", f"unsupported native type {r['native_type']}: no rule evaluates it"
            unsupported.append({"id": r["id"], "native_type": r["native_type"], "name": r["name"], "status": "unknown",
                                "reason": note, **cite(b.ev, r, [])})
        elif not statuses:
            status = "not_evaluated"
            note = ("type is not covered by the requested rule packs" if r["type"] not in rule_types
                    else "no requested rule applies to this resource (for example a provider-managed policy)")
        else:
            status = "fail" if "fail" in statuses else "unknown" if "unknown" in statuses else "pass"
            note = None
        resources.append({"id": r["id"], "type": r["type"], "native_type": r["native_type"], "name": r["name"],
                          "status": status, "evaluated_rules": len(statuses), "note": note})

    types = []
    for t, n in sorted(Counter(r["type"] for r in inv).items()):
        types.append({"type": t, "count": n, "covered": t in rule_types and t != "unsupported",
                      "rules": sorted(rule_types.get(t, [])),
                      "native_types": sorted({r["native_type"] for r in inv if r["type"] == t})})
    rules = []
    for r in b.rules:
        c = Counter(x["status"] for x in b.results if x["rule_id"] == r["id"])
        rules.append({"rule_id": r["id"], "title": r["title"], "pack": r["pack"], "severity": r["severity"],
                      "resource_types": r["resource_types"], "evaluated": sum(c.values()),
                      **{s: c.get(s, 0) for s in STATUSES}})
    status_counts = Counter(r["status"] for r in resources)
    totals = {"checks": len(b.results), **{s: sum(x["status"] == s for x in b.results) for s in STATUSES},
              "resources": len(inv), "resources_unsupported": len(unsupported),
              "resources_not_evaluated": status_counts.get("not_evaluated", 0),
              "resources_by_status": dict(sorted(status_counts.items()))}
    return {"rules": rules, "results": results, "resource_types": types, "resources": resources,
            "unsupported": unsupported, "totals": totals,
            "packs_without_rules_for_provider": sorted({r["pack"] for r in b.pack_rules} - {r["pack"] for r in b.rules},
                                                       key=["storage", "iam", "network", "audit",
                                                            "relationships"].index)}


def coverage_statement(b: Bundle, cov: dict[str, Any]) -> tuple[str, bool]:
    t = cov["totals"]
    uncovered = [x["type"] for x in cov["resource_types"] if not x["covered"]]
    complete = t["unknown"] == 0 and t["resources_unsupported"] == 0 and not uncovered
    evaluated = t["resources"] - t["resources_unsupported"] - t["resources_not_evaluated"]
    native_unsupported = sorted({u["native_type"] for u in cov["unsupported"]})
    parts = [
        f"Evaluated {_plural(len(b.rules), 'rule')} from the {', '.join(b.params['rule_packs'])} "
        f"pack{'s' if len(b.params['rule_packs']) > 1 else ''} against {evaluated} of {t['resources']} resources in "
        f"{b.params['snapshot']}: {_plural(t['checks'], 'check')}, {t['pass']} passed, {t['fail']} failed, "
        f"{t['unknown']} unknown.",
    ]
    if t["unknown"]:
        parts.append(f"{_plural(t['unknown'], 'unknown check')} {'relies' if t['unknown'] == 1 else 'rely'} on "
                     "configuration semantics these rules do not evaluate (for example IAM Conditions, NotAction, "
                     "unexpanded prefix lists or service tags) and are neither passes nor failures.")
    else:
        parts.append("No check returned unknown.")
    if native_unsupported:
        parts.append(f"{_plural(t['resources_unsupported'], 'resource')} of unsupported types "
                     f"({', '.join(native_unsupported)}) were inventoried but not evaluated.")
    if t["resources_not_evaluated"]:
        parts.append(f"{_plural(t['resources_not_evaluated'], 'resource')} of covered types had no applicable rule.")
    uncovered_known = [x for x in uncovered if x != "unsupported"]
    if uncovered_known:
        parts.append(f"Resource types present but not covered by the requested packs: {', '.join(uncovered_known)}.")
    parts.append("Coverage is complete." if complete else
                 "Coverage is partial: passing checks describe only what was evaluated, not the whole configuration.")
    return " ".join(parts), complete


def summary(b: Bundle, cov: dict[str, Any]) -> dict[str, Any]:
    statement, complete = coverage_statement(b, cov)
    t = cov["totals"]
    sev = Counter(f["severity"] for f in b.findings)
    exc = Counter(e["state"] for e in b.exceptions)
    rem = b.remediation["counts"]
    return {
        "snapshot": b.params["snapshot"], "provider": b.provider, "as_of": b.params["as_of"],
        "rule_packs": b.params["rule_packs"], "remediation_mode": b.params["remediation"],
        "checks": {"evaluated": t["checks"], "passed": t["pass"], "failed": t["fail"], "unknown": t["unknown"]},
        "findings": {"total": len(b.findings), "active": sum(f["status"] == "active" for f in b.findings),
                     "excepted": sum(f["status"] == "excepted" for f in b.findings),
                     "by_severity": {s: sev.get(s, 0) for s in ("critical", "high", "medium", "low")}},
        "resources": {"present": t["resources"], "unsupported": t["resources_unsupported"],
                      "not_evaluated": t["resources_not_evaluated"],
                      "evaluated": t["resources"] - t["resources_unsupported"] - t["resources_not_evaluated"]},
        "resource_types": {"present": [x["type"] for x in cov["resource_types"]],
                           "covered": [x["type"] for x in cov["resource_types"] if x["covered"]],
                           "not_covered": [x["type"] for x in cov["resource_types"] if not x["covered"]]},
        "rules": {"evaluated": [r["id"] for r in b.rules],
                  "requested_not_applicable": sorted({r["id"] for r in b.pack_rules} - {r["id"] for r in b.rules}),
                  "packs_without_rules_for_provider": cov["packs_without_rules_for_provider"]},
        "exceptions": {s: exc.get(s, 0) for s in ("active", "expired", "rejected", "not_yet_active")},
        "remediation": {k: rem[k] for k in ("proposed", "accepted", "rejected", "withheld", "not_proposed")},
        "relationships": {"edges": len(b.ev.edges), "unresolved": len(b.ev.unresolved)},
        "complete_coverage": complete,
        "coverage_statement": statement,
    }


def report(b: Bundle, s: dict[str, Any], cov: dict[str, Any]) -> str:
    lines = [f"# Policy Forge run: {s['snapshot']}", "",
             f"Synthetic snapshot `{s['snapshot']}` ({s['provider']}), exceptions evaluated as of {s['as_of']}, "
             f"rule packs: {', '.join(s['rule_packs'])}, remediation: {s['remediation_mode']}.", "",
             "## Coverage", "", s["coverage_statement"], "",
             f"Complete coverage: **{'yes' if s['complete_coverage'] else 'no'}**.", "",
             "| Rule | Pack | Severity | Pass | Fail | Unknown |", "| --- | --- | --- | --- | --- | --- |"]
    lines += [f"| {r['rule_id']} {r['title']} | {r['pack']} | {r['severity']} | {r['pass']} | {r['fail']} | "
              f"{r['unknown']} |" for r in cov["rules"]]
    lines += ["", "## Findings", ""]
    if not b.findings:
        lines.append("No failing checks.")
    for f in b.findings:
        src = f["source"]
        tail = f" (excepted by {f['exception_id']})" if f["exception_id"] else ""
        lines.append(f"- **{f['severity']}** {f['rule_id']} on `{f['resource_name']}`{tail}: {f['reason']} "
                     f"Source: `{src['file']}` line {src['line']}.")
    lines += ["", "## Unknown results", ""]
    unknown = [r for r in cov["results"] if r["status"] == "unknown"]
    lines += [f"- {r['rule_id']} on `{r['resource_id']}`: {r['reason']}" for r in unknown] or ["None."]
    lines += ["", "## Unsupported resources", ""]
    lines += [f"- `{u['id']}` ({u['native_type']}): inventoried, not evaluated."
              for u in cov["unsupported"]] or ["None."]
    lines += ["", "## Exceptions", ""]
    lines += [f"- {e['id']} ({e['rule_id']} on `{e['resource_id']}`): **{e['state']}**, {e['effect']}"
              + (f" Problems: {'; '.join(e['problems'])}." if e["problems"] else "") for e in b.exceptions] or ["None."]
    lines += ["", "## Remediation", "", b.remediation["explanation"], ""]
    for p in b.remediation["patches"]:
        lines.append(f"- {p['id']} for {p['rule_id']} on `{p['resource_id']}`: **{p['status']}**. {p['reason']}")
    for n in b.remediation["not_proposed"]:
        lines.append(f"- not proposed for {n['rule_id']} on `{n['resource_id']}`: {n['reason']}")
    lines += ["", "## Limitations", "",
              "- Snapshots are synthetic and offline; nothing here reflects a live cloud account.",
              "- Only the rules listed above were evaluated. A pass means a rule's test did not fail, not that the "
              "resource is secure.",
              "- Patches are local desired-state edits of the captured JSON files, verified by re-evaluation; they "
              "have not been applied to any cloud account.", ""]
    return "\n".join(lines)


def _checks(b: Bundle, s: dict[str, Any], cov: dict[str, Any], texts: dict[str, str], sensitive: set[str]):
    t = cov["totals"]
    leaks = {name: redact.leaks(text, sensitive) for name, text in texts.items()}
    banned = sorted(name for name, text in texts.items() if BANNED.search(text))
    size = sum(len(x.encode()) for x in texts.values())
    rule_sum = {s: sum(r[s] for r in cov["rules"]) for s in STATUSES}
    return [
        {"id": "counts_reconcile",
         "ok": len(b.findings) == t["fail"] == s["checks"]["failed"] == rule_sum["fail"]
         and t["pass"] == rule_sum["pass"] and t["unknown"] == rule_sum["unknown"]
         and s["findings"]["active"] + s["findings"]["excepted"] == len(b.findings),
         "detail": f"{len(b.findings)} findings, {t['fail']} failing checks, per-rule totals {rule_sum}"},
        {"id": "no_sensitive_value_published", "ok": not any(leaks.values()),
         "detail": "; ".join(f"{k}: {len(v)} hit(s)" for k, v in sorted(leaks.items()) if v)
         or f"{len(texts)} output files scanned against {len(sensitive)} sensitive raw values and credential patterns"},
        {"id": "no_cloud_command_invoked", "ok": set(b.launched) <= {"bash", "pwsh", "opa", "conftest", "jq"},
         "detail": "executables launched: " + ", ".join(b.launched)},
        {"id": "coverage_statement_consistent",
         "ok": s["complete_coverage"] == (t["unknown"] == 0 and t["resources_unsupported"] == 0
                                          and not s["resource_types"]["not_covered"])
         and ("unknown" in s["coverage_statement"]) and not banned
         and (s["complete_coverage"] or "partial" in s["coverage_statement"]),
         "detail": "banned wording in: " + ", ".join(banned) if banned else "statement matches the counts"},
        {"id": "rule_tests_passed", "ok": b.rule_tests["passed"],
         "detail": f"{b.rule_tests['totals']['rules_passed']}/{b.rule_tests['totals']['rules']} rules with passing "
                   "positive, negative and boundary fixtures"},
        {"id": "inventory_hygiene_passed", "ok": b.ev.conftest["passed"],
         "detail": f"{len(b.ev.conftest['failures'])} Conftest failures on the normalized inventory"},
        {"id": "committed_snapshot_unchanged", "ok": b.snapshot_unchanged,
         "detail": "snapshot file hashes are identical before and after the run"},
        {"id": "output_size", "ok": size < MAX_BYTES, "detail": f"{size} bytes"},
    ]


def write(b: Bundle, out_dir: Path, sensitive: set[str]) -> dict[str, Any]:
    out_dir.mkdir(parents=True, exist_ok=True)
    cov = coverage(b)
    s = summary(b, cov)
    rem = {k: v for k, v in b.remediation.items()}
    if rem["combined"] is not None:
        rem["combined"] = {k: v for k, v in rem["combined"].items() if k != "diff"}
    texts: dict[str, str] = {
        "inventory.json": dumps({"snapshot": b.params["snapshot"], "provider": b.provider,
                                 "resources": b.ev.inventory, "redactions": b.ev.redactions}),
        "relationships.json": dumps({"edges": b.ev.edges, "unresolved": b.ev.unresolved}),
        "coverage.json": dumps(cov),
        "findings.json": dumps({"findings": b.findings}),
        "exceptions.json": dumps({"as_of": b.params["as_of"], "registry": "exceptions/registry.json",
                                  "entries": b.exceptions, "counts": s["exceptions"]}),
        "conftest.json": dumps({"tool": "conftest test --output json --policy policy/conftest",
                                "inventory": b.ev.conftest, "exceptions_registry": b.exc_hygiene}),
        "rule_tests.json": dumps(b.rule_tests),
        "remediation.json": dumps(rem),
        "catalog.json": dumps({"catalog_version": b.catalog["catalog_version"], "rules": b.pack_rules}),
        "summary.json": dumps(s),
        "report.md": report(b, s, cov),
    }
    if b.params["remediation"] == "propose":
        combined = b.remediation["combined"]
        texts["remediation.patch"] = combined["diff"] if combined else ""
    texts["manifest.json"] = dumps({
        "package": "policyforge", "package_version": __version__, "params": b.params,
        "snapshot": {"name": b.manifest["name"], "provider": b.provider, "captured_at": b.manifest["captured_at"],
                     "synthetic": True, "files": b.hashes},
        "tools": b.versions, "input_manifest_hash": b.input_hash,
        "outputs": {name: hashlib.sha256(text.encode()).hexdigest() for name, text in sorted(texts.items())},
    })
    checks = _checks(b, s, cov, texts, sensitive)
    texts["checks.json"] = dumps({"checks": checks, "passed": all(c["ok"] for c in checks)})
    for name, text in texts.items():
        (out_dir / name).write_text(text)
    return s


# ------------------------------------------------------------------ validation
def _schema() -> dict[str, Any]:
    return json.loads((ROOT / "schemas" / "outputs.schema.json").read_text())


def validate(out_dir: Path) -> list[str]:
    """Problems with a finished run directory; an empty list means it is valid."""
    out_dir = Path(out_dir)
    problems: list[str] = []
    missing = [f for f in REQUIRED if not (out_dir / f).is_file()]
    if missing:
        return [f"missing output file: {f}" for f in missing]
    data: dict[str, Any] = {}
    for f in JSON_FILES:
        try:
            data[f] = json.loads((out_dir / f).read_text())
        except ValueError as exc:
            problems.append(f"{f}: not valid JSON ({exc})")
    if problems:
        return problems
    schema = _schema()
    for f in JSON_FILES:
        sub = {"$schema": schema["$schema"], "$defs": schema["$defs"], "$ref": f"#/$defs/{f.removesuffix('.json')}"}
        for e in sorted(Draft202012Validator(sub).iter_errors(data[f]), key=lambda e: list(e.path))[:5]:
            problems.append(f"{f}: {'/'.join(map(str, e.path)) or '(root)'}: {e.message[:200]}")
    if problems:
        return problems

    m, s, cov, fnd = data["manifest.json"], data["summary.json"], data["coverage.json"], data["findings.json"]
    mode = m["params"]["remediation"]
    patch = out_dir / "remediation.patch"
    if mode == "propose" and not patch.is_file():
        problems.append("remediation.patch is missing although remediation was proposed")
    if mode == "none" and patch.exists():
        problems.append("remediation.patch exists although remediation was not requested")
    files = sorted(p.name for p in out_dir.iterdir())
    expected = sorted(REQUIRED + (["remediation.patch"] if mode == "propose" else []))
    if files != expected:
        problems.append(f"unexpected files in run directory: {sorted(set(files) - set(expected))}")
    for name, digest in m["outputs"].items():
        if hashlib.sha256((out_dir / name).read_bytes()).hexdigest() != digest:
            problems.append(f"manifest hash mismatch for {name}")
    t = cov["totals"]
    fails = [r for r in cov["results"] if r["status"] == "fail"]
    if not (len(fnd["findings"]) == len(fails) == t["fail"] == s["checks"]["failed"]):
        problems.append("finding count does not match the failing checks in coverage and summary")
    if {f["id"] for f in fnd["findings"]} != {f"{r['rule_id']}::{r['resource_id']}" for r in fails}:
        problems.append("findings do not correspond one-to-one with failing coverage results")
    for k in ("pass", "unknown"):
        if sum(r["status"] == k for r in cov["results"]) != t[k]:
            problems.append(f"coverage totals for {k} do not match the results")
    if s["checks"] != {"evaluated": t["checks"], "passed": t["pass"], "failed": t["fail"], "unknown": t["unknown"]}:
        problems.append("summary check counts do not match coverage totals")
    if s["findings"]["excepted"] != sum(f["status"] == "excepted" for f in fnd["findings"]):
        problems.append("summary excepted count does not match findings")
    for f in fnd["findings"]:
        if (f["status"] == "excepted") != (f["exception_id"] is not None):
            problems.append(f"{f['id']}: excepted status and exception id disagree")
    active = {(e["rule_id"], e["resource_id"]) for e in data["exceptions.json"]["entries"] if e["state"] == "active"}
    for f in fnd["findings"]:
        if f["status"] == "excepted" and (f["rule_id"], f["resource_id"]) not in active:
            problems.append(f"{f['id']}: excepted without an active exception")
    complete = t["unknown"] == 0 and t["resources_unsupported"] == 0 and not s["resource_types"]["not_covered"]
    if s["complete_coverage"] != complete:
        problems.append("complete_coverage does not follow from the coverage totals")
    if t["unknown"] and "unknown" not in s["coverage_statement"]:
        problems.append("coverage_statement does not mention unknown results")
    if not data["checks.json"]["passed"]:
        failed = [c["id"] for c in data["checks.json"]["checks"] if not c["ok"]]
        problems.append("self-checks failed: " + ", ".join(failed))
    size = 0
    for p in out_dir.iterdir():
        text = p.read_text()
        size += len(text.encode())
        if BANNED.search(text):
            problems.append(f"{p.name}: contains wording that presents results as compliance")
        if redact.SENSITIVE_VALUE.search(text):
            problems.append(f"{p.name}: contains a credential-like value")
    if size >= MAX_BYTES:
        problems.append(f"run is {size} bytes, over the {MAX_BYTES} byte limit")
    rem = data["remediation.json"]
    if mode == "propose" and rem["mode"] != "propose" or mode == "none" and rem["mode"] != "none":
        problems.append("remediation.json mode does not match the request")
    return problems
