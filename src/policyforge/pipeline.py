"""Policy Forge pipeline: adapter -> inventory validation -> source lines -> redaction -> relationship graph ->
Conftest hygiene -> OPA evaluation -> exceptions -> optional remediation with re-verification -> outputs."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from jsonschema import Draft202012Validator

from policyforge import __version__, outputs, redact
from policyforge.jsonpos import Scan

ROOT = Path(__file__).resolve().parents[2]
PACKS = ["storage", "iam", "network", "audit", "relationships"]
ALLOWED_EXECUTABLES = {"bash", "pwsh", "opa", "conftest", "jq"}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


class InputError(Exception):
    """Invalid request or bad input (exit 2)."""


class OutputError(Exception):
    """Outputs failed validation or self-checks (exit 1)."""


def dumps(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_json(path: Path) -> Any:
    return json.loads(path.read_text())


# ------------------------------------------------------------------ request
def request_problems(params: dict[str, Any]) -> list[str]:
    """Problems beyond the request schema: rule packs must be in canonical order (one set is one request)."""
    packs = params.get("rule_packs") if isinstance(params, dict) else None
    if not isinstance(packs, list) or not all(p in PACKS for p in packs):
        return []
    if packs != sorted(packs, key=PACKS.index):
        return ["rule_packs: list packs in the canonical order " + ", ".join(PACKS)]
    return []


def schema_problems(params: Any) -> list[str]:
    validator = Draft202012Validator(load_json(ROOT / "schemas" / "request.schema.json"))
    return [f"{'/'.join(map(str, e.path)) or 'request'}: {e.message}" for e in validator.iter_errors(params)]


# ------------------------------------------------------------------ tools
@dataclass
class Tools:
    """Locates and runs the external tools, recording every executable launched."""

    launched: list[str] = field(default_factory=list)

    def path(self, name: str, required: bool = True) -> str | None:
        found = os.environ.get(f"PF_{name.upper()}") or shutil.which(name)
        if found is None and required:
            raise RuntimeError(f"required tool not found on PATH: {name} (or set PF_{name.upper()})")
        return found

    def run(self, argv: list[str], *, cwd: Path | None = None, env: dict[str, str] | None = None,
            ok_codes: tuple[int, ...] = (0,)) -> subprocess.CompletedProcess[str]:
        self.launched.append(Path(argv[0]).name)
        proc = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True, timeout=300, check=False)
        if proc.returncode not in ok_codes:
            raise RuntimeError(f"{Path(argv[0]).name} exited {proc.returncode}: {proc.stderr.strip()[-2000:]}")
        return proc

    def versions(self) -> dict[str, str | None]:
        def first(argv: list[str], pattern: str, env: dict[str, str] | None = None) -> str | None:
            if argv[0] is None:
                return None
            out = self.run(argv, env=env).stdout
            m = re.search(pattern, out)
            return m.group(1) if m else out.strip().splitlines()[0]

        with tempfile.TemporaryDirectory() as home:
            pwsh = first([self.path("pwsh", required=False), "-NoProfile", "-NonInteractive", "-Command",
                          "$PSVersionTable.PSVersion.ToString()"], r"(\S+)", env=self.pwsh_env(home))
        return {
            "opa": first([self.path("opa"), "version"], r"Version:\s*(\S+)"),
            "conftest": first([self.path("conftest"), "--version"], r"Conftest:\s*(\S+)"),
            "bash": first([self.path("bash"), "--version"], r"version\s+(\S+)"),
            "jq": first([self.path("jq", required=False), "--version"], r"jq-(\S+)"),
            "pwsh": pwsh,
        }

    def pwsh_env(self, home: str) -> dict[str, str]:
        return {**os.environ, "HOME": home, "POWERSHELL_UPDATECHECK": "Off", "POWERSHELL_TELEMETRY_OPTOUT": "1",
                "DOTNET_CLI_TELEMETRY_OPTOUT": "1"}


# ------------------------------------------------------------------ evaluation
@dataclass
class Evaluation:
    inventory: list[dict[str, Any]]
    redactions: list[dict[str, str]]
    edges: list[dict[str, str]]
    unresolved: list[dict[str, str]]
    results: list[dict[str, Any]]
    conftest: dict[str, Any]
    scans: dict[str, Scan]


def _inventory_validator() -> Draft202012Validator:
    return Draft202012Validator(load_json(ROOT / "schemas" / "inventory.schema.json"))


def run_adapter(snapshot_dir: Path, provider: str, tools: Tools) -> list[dict[str, Any]]:
    if provider == "aws":
        proc = tools.run([tools.path("bash"), str(ROOT / "adapters" / "aws" / "normalize.sh"), str(snapshot_dir)],
                         ok_codes=(0, 1, 2, 3, 4, 5))
    elif provider == "azure":
        with tempfile.TemporaryDirectory() as home:
            proc = tools.run([tools.path("pwsh"), "-NoProfile", "-NonInteractive", "-File",
                              str(ROOT / "adapters" / "azure" / "Normalize-Azure.ps1"), str(snapshot_dir)],
                             env=tools.pwsh_env(home), ok_codes=(0, 1, 2))
    else:
        raise InputError(f"unknown provider {provider!r}")
    if proc.returncode != 0:
        raise InputError(f"adapter failed for {snapshot_dir.name}: {proc.stderr.strip()[-2000:]}")
    records = []
    for n, line in enumerate(proc.stdout.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            records.append(json.loads(line))
        except ValueError as exc:
            raise InputError(f"adapter output line {n} is not JSON: {exc}") from exc
    return records


def raw_locations(node: Any) -> list[str]:
    """Every 'snapshots/...#pointer' string inside a properties tree."""
    if isinstance(node, dict):
        return [loc for v in node.values() for loc in raw_locations(v)]
    if isinstance(node, list):
        return [loc for v in node for loc in raw_locations(v)]
    if isinstance(node, str) and node.startswith("snapshots/") and "#" in node:
        return [node]
    return []


def resolve_refs(inventory: list[dict[str, Any]]) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    ids = {r["id"] for r in inventory}
    by_lower = {r["id"].lower(): r["id"] for r in inventory if r["provider"] == "azure"}
    native: dict[str, list[str]] = {}
    for r in inventory:
        nid = r["id"].split(":", 2)[2]
        native.setdefault(nid, []).append(r["id"])
        if r["provider"] == "azure":
            native.setdefault(nid.lower(), []).append(r["id"])
    edges, unresolved = set(), set()
    for r in inventory:
        for ref in r["refs"]:
            t = ref["target"]
            hit = t if t in ids else by_lower.get(t.lower()) if r["provider"] == "azure" else None
            if hit is None:
                cands = native.get(t) or (native.get(t.lower()) if r["provider"] == "azure" else None) or []
                hit = cands[0] if len(set(cands)) == 1 else None
            if hit is None:
                unresolved.add((r["id"], ref["kind"], t))
            else:
                edges.add((r["id"], hit, ref["kind"]))
    return ([{"from": f, "to": t, "kind": k} for f, t, k in sorted(edges)],
            [{"from": f, "kind": k, "target": t} for f, k, t in sorted(unresolved)])


def conftest_check(tools: Tools, label: str, payload: Any, workdir: Path) -> dict[str, Any]:
    path = workdir / f"{label}.json"
    path.write_text(json.dumps(payload))
    proc = tools.run([tools.path("conftest"), "test", "--no-color", "--output", "json", "--policy",
                      str(ROOT / "policy" / "conftest"), "--data", str(ROOT / "policy" / "catalog.json"), str(path)],
                     ok_codes=(0, 1))
    try:
        report = json.loads(proc.stdout)
    except ValueError as exc:
        raise RuntimeError(f"conftest output is not JSON: {proc.stderr.strip()[-500:]}") from exc
    fails = sorted(f["msg"] for entry in report for f in entry.get("failures") or [])
    warns = sorted(w["msg"] for entry in report for w in entry.get("warnings") or [])
    return {"input": label, "successes": sum(int(e.get("successes", 0)) for e in report),
            "failures": fails, "warnings": warns, "passed": not fails}


def opa_results(tools: Tools, payload: dict[str, Any], workdir: Path) -> list[dict[str, Any]]:
    path = workdir / "opa-input.json"
    path.write_text(json.dumps(payload))
    proc = tools.run([tools.path("opa"), "eval", "--v1-compatible", "--format", "json", "--data",
                      str(ROOT / "policy" / "rules"), "--input", str(path), "data.policyforge.results"])
    out = json.loads(proc.stdout)
    try:
        value = out["result"][0]["expressions"][0]["value"]
    except (KeyError, IndexError) as exc:
        raise RuntimeError("opa returned no value for data.policyforge.results") from exc
    return sorted(value, key=lambda r: (r["rule_id"], r["resource_id"]))


def evaluate(snapshot_dir: Path, manifest: dict[str, Any], context: dict[str, Any], tools: Tools) -> Evaluation:
    """Full evaluation of one snapshot directory (the committed one or a patched temporary copy)."""
    name, provider = manifest["name"], manifest["provider"]
    records = run_adapter(snapshot_dir, provider, tools)
    validator = _inventory_validator()
    seen: set[str] = set()
    for rec in records:
        errors = sorted(validator.iter_errors(rec), key=lambda e: list(e.path))
        if errors:
            e = errors[0]
            raise InputError(f"adapter record {rec.get('id', '?')}: {'/'.join(map(str, e.path))}: {e.message}")
        if not rec["id"].startswith(f"{rec['provider']}:{rec['type']}:") or rec["provider"] != provider:
            raise InputError(f"adapter record {rec['id']}: id must be '<provider>:<type>:<native id>'")
        if rec["id"] in seen:
            raise InputError(f"adapter emitted duplicate id {rec['id']}")
        seen.add(rec["id"])

    prefix = f"snapshots/{name}/"
    scans: dict[str, Scan] = {}

    def scan(file: str) -> Scan:
        if file not in scans:
            if not file.startswith(prefix) or "/" in file[len(prefix):]:
                raise InputError(f"source file {file} is outside snapshot {name}")
            try:
                scans[file] = Scan((snapshot_dir / file[len(prefix):]).read_text())
            except (OSError, ValueError) as exc:
                raise InputError(f"cannot scan {file}: {exc}") from exc
        return scans[file]

    for f in manifest["files"]:
        scan(prefix + f)
    redactions: list[dict[str, str]] = []
    for rec in records:
        src = rec["source"]
        line = scan(src["file"]).lines.get(src["pointer"])
        if line is None:
            raise InputError(f"{rec['id']}: pointer {src['pointer']} not found in {src['file']}")
        src["line"] = line
        for loc in raw_locations(rec["properties"]):
            scan(loc.split("#", 1)[0])
        rec["properties"], found = redact.redact_tree(rec["properties"], "/properties")
        redactions += [{"resource_id": rec["id"], **r} for r in found]
    inventory = sorted(records, key=lambda r: r["id"])
    edges, unresolved = resolve_refs(inventory)
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        hygiene = conftest_check(tools, "inventory", {"resources": inventory}, work)
        payload = {"resources": inventory, "edges": edges, "unresolved": unresolved, "context": context}
        results = opa_results(tools, payload, work)
    return Evaluation(inventory, sorted(redactions, key=lambda r: (r["resource_id"], r["path"])), edges, unresolved,
                      results, hygiene, scans)


# ------------------------------------------------------------------ evidence locations and excerpts
def locate(ev: Evaluation, raw: str) -> dict[str, Any] | None:
    file, _, ptr = raw.partition("#")
    scan = ev.scans.get(file)
    if scan is None:
        return None
    return {"file": file, "pointer": ptr, "line": scan.nearest_line(ptr)}


def excerpt(ev: Evaluation, file: str, lines: list[int], context: int = 6, cap: int = 40) -> dict[str, Any]:
    scan = ev.scans[file]
    text = redact.redacted_text(scan).splitlines()
    lines = sorted(set(lines))
    lo, hi = lines[0] - context, lines[-1] + context
    if hi - lo + 1 > cap:
        hi = lines[0] + context
        lines = [n for n in lines if n <= hi]
    lo, hi = max(1, lo), min(len(text), hi)
    return {"first_line": lo, "lines": text[lo - 1 : hi], "cited_lines": lines}


def cite(ev: Evaluation, resource: dict[str, Any], evidence: list[dict[str, Any]]) -> dict[str, Any]:
    """Source of a result: the first cited raw value (or the resource object), cited locations and an excerpt."""
    cited = [loc for item in evidence if isinstance(item.get("raw"), str) for loc in [locate(ev, item["raw"])] if loc]
    seen, uniq = set(), []
    for loc in cited:
        key = (loc["file"], loc["pointer"])
        if key not in seen:
            seen.add(key)
            uniq.append(loc)
    rsrc = {k: resource["source"][k] for k in ("file", "pointer", "line")}
    primary = uniq[0] if uniq else rsrc
    same_file = [loc["line"] for loc in uniq if loc["file"] == primary["file"]] or [primary["line"]]
    return {"source": {**primary, "excerpt": excerpt(ev, primary["file"], same_file)}, "cited": uniq or [rsrc]}


# ------------------------------------------------------------------ exceptions
def evaluate_exceptions(registry: dict[str, Any], hygiene: dict[str, Any], as_of: str, rule_ids: set[str],
                        failing: set[tuple[str, str]], resource_ids: set[str]) -> list[dict[str, Any]]:
    rejected: dict[str, list[str]] = {}
    for msg in hygiene["failures"]:
        eid, _, reason = msg.partition(": ")
        rejected.setdefault(eid, []).append(reason)
    today = date.fromisoformat(as_of)
    out = []
    for e in registry.get("exceptions", []):
        eid = str(e.get("id", "unidentified"))
        entry = {k: e.get(k) for k in ("id", "rule_id", "resource_id", "reason", "owner", "ticket", "created",
                                       "expires")}
        key = (e.get("rule_id"), e.get("resource_id"))
        entry["in_scope"] = e.get("rule_id") in rule_ids and e.get("resource_id") in resource_ids
        entry["matches_failing_result"] = key in failing
        if eid in rejected:
            entry.update(state="rejected", problems=sorted(rejected[eid]),
                         effect="ignored: rejected by the registry hygiene checks")
        else:
            created, expires = date.fromisoformat(e["created"]), date.fromisoformat(e["expires"])
            if today < created:
                state, effect = "not_yet_active", "ignored: created after as_of"
            elif today > expires:
                state, effect = "expired", "expired: any matching finding stays active"
            else:
                state = "active"
                effect = ("excepts the matching finding" if key in failing
                          else "active, but its rule or resource is not evaluated in this run" if not entry["in_scope"]
                          else "active, but no failing result matches")
            entry.update(state=state, problems=[], effect=effect)
        out.append(entry)
    return sorted(out, key=lambda x: str(x["id"]))


# ------------------------------------------------------------------ run
def snapshot_hashes(snapshot_dir: Path, name: str) -> list[dict[str, Any]]:
    return [{"path": f"snapshots/{name}/{p.name}", "sha256": sha256(p.read_bytes()), "bytes": p.stat().st_size}
            for p in sorted(snapshot_dir.iterdir(), key=lambda p: p.name) if p.is_file()]


def run(params: dict[str, Any], out_dir: Path) -> dict[str, Any]:
    problems = schema_problems(params) or request_problems(params)
    if problems:
        raise InputError("; ".join(problems))
    out_dir = Path(out_dir)
    if out_dir.exists() and (not out_dir.is_dir() or any(out_dir.iterdir())):
        raise InputError(f"output directory must not exist or must be empty: {out_dir}")
    name = params["snapshot"]
    snapshot_dir = ROOT / "snapshots" / name
    try:
        manifest = load_json(snapshot_dir / "manifest.json")
        context = load_json(snapshot_dir / "context.json")
    except (OSError, ValueError) as exc:
        raise InputError(f"snapshot {name} is unreadable: {exc}") from exc
    if manifest.get("name") != name or manifest.get("synthetic") is not True:
        raise InputError(f"snapshot {name}: manifest name must match and synthetic must be true")
    provider = manifest["provider"]
    catalog = load_json(ROOT / "policy" / "catalog.json")
    packs = params["rule_packs"]
    pack_rules = [r for r in catalog["rules"] if r["pack"] in packs]
    rules = [r for r in pack_rules if provider in r["providers"]]
    rule_ids = {r["id"] for r in rules}

    tools = Tools()
    hashes = snapshot_hashes(snapshot_dir, name)
    ev = evaluate(snapshot_dir, manifest, context, tools)
    results = [r for r in ev.results if r["rule_id"] in rule_ids]
    by_res = {r["id"]: r for r in ev.inventory}
    failing = {(r["rule_id"], r["resource_id"]) for r in results if r["status"] == "fail"}

    registry = load_json(ROOT / "exceptions" / "registry.json")
    with tempfile.TemporaryDirectory() as tmp:
        exc_hygiene = conftest_check(tools, "exceptions-registry", registry, Path(tmp))
    exceptions = evaluate_exceptions(registry, exc_hygiene, params["as_of"], rule_ids, failing, set(by_res))
    active_exc = {(e["rule_id"], e["resource_id"]): e["id"] for e in exceptions if e["state"] == "active"}

    from policyforge import remediate  # local import: remediate imports this module

    rules_by_id = {r["id"]: r for r in rules}
    findings = []
    for r in results:
        if r["status"] != "fail":
            continue
        meta, res = rules_by_id[r["rule_id"]], by_res[r["resource_id"]]
        exc_id = active_exc.get((r["rule_id"], r["resource_id"]))
        findings.append({
            "id": f"{r['rule_id']}::{r['resource_id']}", "rule_id": r["rule_id"], "title": meta["title"],
            "pack": meta["pack"], "severity": meta["severity"], "resource_id": res["id"], "resource_type": res["type"],
            "resource_name": res["name"], "provider": provider, "status": "excepted" if exc_id else "active",
            "exception_id": exc_id, "reason": r["reason"], "evidence": r["evidence"],
            **cite(ev, res, r["evidence"]),
            "remediation": {"kind": meta["remediation"]["kind"], "patch_id": None, "patch_status": None},
        })
    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["rule_id"], f["resource_id"]))

    rem = remediate.propose(params, snapshot_dir, manifest, context, tools, ev, results, findings, rules_by_id) \
        if params["remediation"] == "propose" else remediate.not_requested()
    for f in findings:
        for p in rem["patches"]:
            if p["finding_id"] == f["id"]:
                f["remediation"].update(patch_id=p["id"], patch_status=p["status"])
        for n in rem["not_proposed"]:
            if n["finding_id"] == f["id"]:
                f["remediation"].update(patch_status="not_proposed")

    rule_tests = run_rule_tests(tools, [r["id"] for r in pack_rules])
    versions = tools.versions()
    hashes_after = snapshot_hashes(snapshot_dir, name)
    snapshot_files = {h["path"]: h["sha256"] for h in hashes}
    input_hash = sha256(canonical({"params": params, "snapshot_files": snapshot_files,
                                   "package_version": __version__}).encode())
    bundle = outputs.Bundle(
        params=params, manifest=manifest, context=context, provider=provider, catalog=catalog, pack_rules=pack_rules,
        rules=rules, ev=ev, results=results, findings=findings, exceptions=exceptions, exc_hygiene=exc_hygiene,
        remediation=rem, rule_tests=rule_tests, versions=versions, hashes=hashes, input_hash=input_hash,
        launched=sorted(set(tools.launched)), snapshot_unchanged=hashes == hashes_after,
        coverage_unknown=[cite_unknown(ev, by_res, r) for r in results if r["status"] == "unknown"],
    )
    summary = outputs.write(bundle, out_dir, sensitive=all_sensitive_values(ev))
    problems = outputs.validate(out_dir)
    if problems:
        raise OutputError("; ".join(problems[:20]))
    return summary


def cite_unknown(ev: Evaluation, by_res: dict[str, dict[str, Any]], r: dict[str, Any]) -> dict[str, Any]:
    return {"rule_id": r["rule_id"], "resource_id": r["resource_id"],
            **cite(ev, by_res[r["resource_id"]], r["evidence"])}


def all_sensitive_values(ev: Evaluation) -> set[str]:
    return set().union(*(redact.sensitive_values(s) for s in ev.scans.values()))


def run_rule_tests(tools: Tools, rule_ids: list[str]) -> dict[str, Any]:
    proc = tools.run([tools.path("opa"), "test", "--v1-compatible", "--format", "json", "policy"], cwd=ROOT,
                     ok_codes=(0, 2))
    tests = json.loads(proc.stdout or "[]")
    per_rule: dict[str, dict[str, Any]] = {}
    other = []
    for t in tests:
        ok = not t.get("fail") and not t.get("error") and not t.get("skip")
        m = re.fullmatch(r"test_(PF_[A-Z]+_\d{3})_(positive|negative|boundary)", t["name"])
        if m:
            rid = m.group(1).replace("_", "-")
            per_rule.setdefault(rid, {})[m.group(2)] = ok
        else:
            other.append({"name": f"{t['package']}.{t['name']}", "passed": ok})
    rules = []
    for rid in rule_ids:
        kinds = {}
        for kind in ("positive", "negative", "boundary"):
            files = sorted(p.name for p in (ROOT / "policy" / "fixtures" / rid).glob(f"{kind}-*.json"))
            kinds[kind] = {"fixtures": len(files), "files": files, "passed": per_rule.get(rid, {}).get(kind, False)}
        passed = all(k["passed"] and k["fixtures"] for k in kinds.values())
        rules.append({"rule_id": rid, "kinds": kinds, "passed": passed})
    return {
        "tool": "opa test --format json policy",
        "rules": rules,
        "other_tests": sorted(other, key=lambda x: x["name"]),
        "totals": {"rule_kinds": 3 * len(rules), "rule_kinds_passed": sum(k["passed"] for r in rules
                                                                           for k in r["kinds"].values()),
                   "rules_passed": sum(r["passed"] for r in rules), "rules": len(rules),
                   "other_passed": sum(o["passed"] for o in other), "other": len(other)},
        "passed": all(r["passed"] for r in rules) and all(o["passed"] for o in other),
    }
