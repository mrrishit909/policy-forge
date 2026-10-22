"""Local-file remediation: RFC 6902 patches against the raw snapshot files, applied to a temporary copy and
re-verified by re-running the whole evaluation. A patch is accepted only if its target finding resolves to pass,
every other result of every rule that applies to the provider (not only the requested packs) keeps its status, every
other finding keeps its reason and evidence, and no resource outside the patched raw paths changes in the normalized
inventory. A diff is published only if it applies exactly as text (lines split on "\n" only, as git does) and none
of its context or changed lines holds a sensitive raw value. Committed snapshots are never modified."""

from __future__ import annotations

import copy
import difflib
import json
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any

from policyforge import redact
from policyforge.jsonpos import resolve, split_lines, split_pointer

PATCH_NOTE = "Restricted to admin_cidrs (Policy Forge proposal)"


class NotProposed(Exception):
    pass


def canonical_text(doc: Any) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def apply_patch(doc: Any, ops: list[dict[str, Any]]) -> Any:
    """Apply RFC 6902 add / replace / remove / test operations to a copy of doc."""
    doc = copy.deepcopy(doc)
    for op in ops:
        parts = split_pointer(op["path"])
        if not parts:
            raise ValueError("whole-document operations are not supported")
        parent = resolve(doc, "".join("/" + p.replace("~", "~0").replace("/", "~1") for p in parts[:-1]))
        last = parts[-1]
        kind = op["op"]
        if kind == "test":
            if resolve(doc, op["path"]) != op["value"]:
                raise ValueError(f"test failed at {op['path']}")
        elif isinstance(parent, list):
            if kind == "add":
                parent.insert(len(parent) if last == "-" else int(last), copy.deepcopy(op["value"]))
            elif kind == "replace":
                parent[int(last)] = copy.deepcopy(op["value"])
            elif kind == "remove":
                del parent[int(last)]
            else:
                raise ValueError(f"unsupported op {kind}")
        elif isinstance(parent, dict):
            if kind == "add":
                parent[last] = copy.deepcopy(op["value"])
            elif kind == "replace":
                if last not in parent:
                    raise ValueError(f"replace of a missing member at {op['path']}")
                parent[last] = copy.deepcopy(op["value"])
            elif kind == "remove":
                del parent[last]
            else:
                raise ValueError(f"unsupported op {kind}")
        else:
            raise ValueError(f"cannot apply {kind} under a scalar at {op['path']}")
    return doc


def _keep_lines(text: str) -> list[str]:
    """Lines with their "\n" terminators, split on "\n" only (never on U+2028 and friends, as splitlines does)."""
    parts = text.split("\n")
    return [p + "\n" for p in parts[:-1]] + ([parts[-1]] if parts[-1] else [])


def unified_diff(path: str, before: str, after: str) -> str:
    body = "".join(difflib.unified_diff(_keep_lines(before), _keep_lines(after), f"a/{path}", f"b/{path}"))
    return f"diff --git a/{path} b/{path}\n{body}" if body else ""


def diff_guard(path: str, before: str, after: str) -> list[str]:
    """Positions (never values) of sensitive raw lines that a diff of before -> after would publish as context or
    changed lines. Uses the same line selection as unified_diff (difflib grouped opcodes, 3 lines of context)."""
    sens_a, sens_b = redact.sensitive_lines(before), redact.sensitive_lines(after)
    hits = set()
    matcher = difflib.SequenceMatcher(None, _keep_lines(before), _keep_lines(after))
    for group in matcher.get_grouped_opcodes(3):
        for _, i1, i2, j1, j2 in group:
            hits |= {f"{path} line {n + 1}" for n in range(i1, i2) if n + 1 in sens_a}
            hits |= {f"{path} new line {n + 1}" for n in range(j1, j2) if n + 1 in sens_b}
    return sorted(hits)


_HUNK = re.compile(r"@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def apply_unified(files: dict[str, str], patch: str) -> dict[str, str]:
    """Strictly apply a unified diff made by unified_diff (exact context, no fuzz, no offset) to texts keyed by
    repo-relative path. Raises ValueError when the patch does not apply as text."""
    out = dict(files)
    lines = patch.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    i = 0
    while i < len(lines):
        if not lines[i].startswith("diff --git ") or i + 2 >= len(lines):
            raise ValueError(f"unexpected patch line {i + 1}")
        if not (lines[i + 1].startswith("--- a/") and lines[i + 2].startswith("+++ b/")):
            raise ValueError(f"missing file header at patch line {i + 2}")
        path = lines[i + 1][6:]
        if lines[i + 2][6:] != path or path not in out:
            raise ValueError(f"patch names an unknown file: {path}")
        src, result, pos = split_lines(out[path]), [], 0
        i += 3
        while i < len(lines) and lines[i].startswith("@@"):
            m = _HUNK.fullmatch(lines[i])
            if not m:
                raise ValueError(f"bad hunk header at patch line {i + 1}")
            start = int(m.group(1)) - (1 if int(m.group(2) or 1) > 0 else 0)
            if start < pos:
                raise ValueError(f"overlapping hunk at patch line {i + 1}")
            result += src[pos:start]
            pos = start
            i += 1
            while i < len(lines) and lines[i][:1] in (" ", "-", "+"):
                tag, body = lines[i][0], lines[i][1:]
                if tag != "+":
                    if pos >= len(src) or src[pos] != body:
                        raise ValueError(f"{path}: context does not match at line {pos + 1}")
                    pos += 1
                if tag != "-":
                    result.append(body)
                i += 1
        out[path] = "\n".join(result + src[pos:]) + "\n"
    return out


# ------------------------------------------------------------------ strategies
def _set(ptr: str, value: Any, doc: Any) -> list[dict[str, Any]]:
    """test + replace when the member exists (and differs), add when it does not."""
    try:
        cur = resolve(doc, ptr)
    except (KeyError, IndexError):
        return [{"op": "add", "path": ptr, "value": value}]
    if cur == value:
        return []
    return [{"op": "test", "path": ptr, "value": cur}, {"op": "replace", "path": ptr, "value": value}]


def _raw(loc: str | None) -> tuple[str, str]:
    if not isinstance(loc, str) or "#" not in loc:
        raise NotProposed("the raw location of the setting is unknown")
    file, _, ptr = loc.partition("#")
    return file, ptr


def _pab(flags: tuple[str, str], resource: dict[str, Any], docs: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    file, ptr = _raw(resource["properties"]["raw"]["guard"])
    try:
        cur = resolve(docs[file], ptr)
    except (KeyError, IndexError):
        cur = None
    if cur is None:
        conf = {f: f in flags for f in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy",
                                        "RestrictPublicBuckets")}
        ops = ([{"op": "test", "path": ptr, "value": None}] if _exists(docs[file], ptr) else [])
        return {file: ops + [{"op": "add", "path": ptr, "value": {"PublicAccessBlockConfiguration": conf}}]}
    ops = []
    for f in flags:
        ops += _set(f"{ptr}/PublicAccessBlockConfiguration/{f}", True, docs[file])
    return {file: ops}


def _exists(doc: Any, ptr: str) -> bool:
    try:
        resolve(doc, ptr)
        return True
    except (KeyError, IndexError):
        return False


def _restrict(resource: dict[str, Any], result: dict[str, Any], docs: dict[str, Any],
              context: dict[str, Any]) -> dict[str, list[dict[str, Any]]]:
    admin = list(context.get("admin_cidrs") or [])
    if not admin:
        raise NotProposed("context.json defines no admin_cidrs to restrict to")
    out: dict[str, list[dict[str, Any]]] = {}
    seen = set()
    for item in result["evidence"]:
        loc = item.get("raw")
        if not loc or loc in seen:
            continue
        seen.add(loc)
        wide = set(item.get("internet_sources") or [])
        file, ptr = _raw(loc)
        rule = resolve(docs[file], ptr)
        ops = out.setdefault(file, [])
        if resource["provider"] == "aws":
            v4 = [r for r in rule.get("IpRanges", []) if r.get("CidrIp") not in wide]
            have = {r.get("CidrIp") for r in v4}
            v4 += [{"CidrIp": c, "Description": PATCH_NOTE} for c in admin if c not in have and ":" not in c]
            v6 = [r for r in rule.get("Ipv6Ranges", []) if r.get("CidrIpv6") not in wide]
            v6 += [{"CidrIpv6": c, "Description": PATCH_NOTE} for c in admin if ":" in c]
            ops += _set(f"{ptr}/IpRanges", v4, docs[file]) + _set(f"{ptr}/Ipv6Ranges", v6, docs[file])
        else:
            prefixes = [s for s in rule.get("SourceAddressPrefix", []) if s not in wide]
            prefixes += [c for c in admin if c not in prefixes]
            ops += _set(f"{ptr}/SourceAddressPrefix", prefixes, docs[file])
    return out


def _flag(prop: str, value: bool):
    def strategy(resource, result, docs, context):
        loc = resource["properties"]["raw"].get(prop)
        if loc is None:
            raise NotProposed(f"the raw source of {prop} is not in the snapshot")
        file, ptr = _raw(loc)
        return {file: _set(ptr, value, docs[file])}

    return strategy


def _categories(resource, result, docs, context):
    if not any(resource["properties"]["destinations"].values()):
        raise NotProposed("the Activity Log export has no destination; the owner must choose one")
    required = context.get("required_activity_log_categories") or ["Administrative", "Security", "Policy"]
    file, ptr = _raw(resource["properties"]["raw"]["categories"])
    logs = resolve(docs[file], ptr)
    ops = []
    for cat in required:
        idx = next((i for i, x in enumerate(logs) if x.get("Category") == cat), None)
        if idx is None:
            ops.append({"op": "add", "path": f"{ptr}/-", "value": {"Category": cat, "Enabled": True}})
        else:
            ops += _set(f"{ptr}/{idx}/Enabled", True, docs[file])
    return {file: ops}


def _storage_guard(flags):
    def strategy(resource, result, docs, context):
        if resource["provider"] == "aws":
            return _pab(flags, resource, docs)
        file, ptr = _raw(resource["properties"]["raw"]["guard"])
        return {file: _set(ptr, False, docs[file])}

    return strategy


STRATEGIES = {
    "PF-STOR-001": _storage_guard(("BlockPublicAcls", "IgnorePublicAcls")),
    "PF-STOR-002": _storage_guard(("BlockPublicPolicy", "RestrictPublicBuckets")),
    "PF-NET-001": _restrict,
    "PF-NET-002": _restrict,
    "PF-AUD-001": _flag("is_logging", True),
    "PF-AUD-002": _flag("multi_region", True),
    "PF-AUD-003": _flag("log_file_validation", True),
    "PF-AUD-004": _categories,
}


# ------------------------------------------------------------------ verification
def _key(r: dict[str, Any]) -> tuple[str, str]:
    return r["rule_id"], r["resource_id"]


def _strip(resource: dict[str, Any]) -> dict[str, Any]:
    out = copy.deepcopy(resource)
    out["source"].pop("line", None)
    return out


def _touched(resource: dict[str, Any], patched: dict[str, list[str]]) -> bool:
    from policyforge.pipeline import raw_locations

    locs = [f"{resource['source']['file']}#{resource['source']['pointer']}"] + raw_locations(resource["properties"])
    for loc in locs:
        file, _, ptr = loc.partition("#")
        for path in patched.get(file, []):
            if path == ptr or path.startswith(ptr + "/") or ptr.startswith(path + "/"):
                return True
    return False


def compare(before, after, targets: set[tuple[str, str]], rule_ids: set[str],
            patched: dict[str, list[str]], requested: set[str] | None = None) -> dict[str, Any]:
    """Regression comparison over every rule in rule_ids (all rules for the provider, so a narrow request cannot
    accept a patch that changes a rule it did not ask for); requested only labels such rules in the reasons."""
    b = {_key(r): r for r in before.results if r["rule_id"] in rule_ids}
    a = {_key(r): r for r in after.results if r["rule_id"] in rule_ids}
    target_status = [{"rule_id": k[0], "resource_id": k[1], "before": b.get(k, {}).get("status"),
                      "after": a.get(k, {}).get("status")} for k in sorted(targets)]
    changed_results, changed_findings = [], []
    for k in sorted(set(a) | set(b)):
        if k in targets:
            continue
        bs, as_ = b.get(k, {}).get("status"), a.get(k, {}).get("status")
        if bs != as_:
            changed_results.append({"rule_id": k[0], "resource_id": k[1], "before": bs, "after": as_})
        elif bs == "fail" and (b[k]["reason"], b[k]["evidence"]) != (a[k]["reason"], a[k]["evidence"]):
            changed_findings.append({"rule_id": k[0], "resource_id": k[1]})
    binv = {r["id"]: r for r in before.inventory}
    ainv = {r["id"]: r for r in after.inventory}
    touched = sorted(i for i in binv if _touched(binv[i], patched))
    changed_resources = sorted(i for i in set(binv) | set(ainv) if i not in touched
                               and (i not in binv or i not in ainv or _strip(binv[i]) != _strip(ainv[i])))
    resolved = all(t["before"] == "fail" and t["after"] == "pass" for t in target_status)
    ok = (resolved and not changed_results and not changed_findings and not changed_resources
          and after.conftest["passed"])
    reasons = []
    if not resolved:
        reasons.append("target finding is not resolved to pass: " + ", ".join(
            f"{t['rule_id']} {t['before']} -> {t['after']}" for t in target_status))
    if changed_results:
        tag = {c["rule_id"]: "" if requested is None or c["rule_id"] in requested else ", outside the requested packs"
               for c in changed_results}
        reasons.append("other rule results change: " + ", ".join(
            f"{c['rule_id']} on {c['resource_id']} ({c['before']} -> {c['after']}{tag[c['rule_id']]})"
            for c in changed_results))
    if changed_findings:
        reasons.append("other findings change their evidence: " + ", ".join(
            f"{c['rule_id']} on {c['resource_id']}" for c in changed_findings))
    if changed_resources:
        reasons.append("resources outside the patched paths change: " + ", ".join(changed_resources))
    if not after.conftest["passed"]:
        reasons.append("the patched inventory fails the Conftest hygiene checks")
    return {"ok": ok, "targets": target_status, "changed_results": changed_results,
            "changed_findings": changed_findings, "changed_resources": changed_resources,
            "touched_resources": touched, "checked_results": len(set(a) | set(b)),
            "checked_resources": len(set(binv) | set(ainv)), "reasons": reasons}


def _patched_copy(snapshot_dir: Path, name: str, root: Path, texts: dict[str, str]) -> Path:
    dest = root / "snapshots" / name
    shutil.copytree(snapshot_dir, dest)
    for file, text in texts.items():
        (dest / file.split("/", 2)[2]).write_text(text)
    return dest


def _publish_problems(before: dict[str, str], after: dict[str, str], diff: str, sensitive: set[str]) -> list[str]:
    """Why a diff may not be published: sensitive raw lines in its context or changes, a credential-like value,
    or a diff that does not reproduce the patched files when applied as text."""
    problems = [h for f in sorted(after) for h in diff_guard(f, before[f], after[f])]
    problems += redact.leaks(diff, sensitive)
    try:
        applied = apply_unified({f: before[f] for f in after}, diff)
        if any(applied[f] != after[f] for f in after):
            problems.append("the diff does not reproduce the patched file when applied as text")
    except (ValueError, KeyError, IndexError) as exc:
        problems.append(f"the diff does not apply as text ({exc})")
    return problems


def propose(params, snapshot_dir, manifest, context, tools, ev, results, findings, rules,
            provider_rule_ids: set[str] | None = None) -> dict[str, Any]:
    from policyforge.pipeline import evaluate

    name = manifest["name"]
    requested = {r["rule_id"] for r in results} | set(rules)
    rule_ids = set(provider_rule_ids or ()) | requested
    by_res = {r["id"]: r for r in ev.inventory}
    by_key = {_key(r): r for r in results}
    originals = {f"snapshots/{name}/{f}": (snapshot_dir / f).read_text() for f in manifest["files"]}
    docs = {f: json.loads(t) for f, t in originals.items()}
    sensitive = set().union(*(redact.sensitive_values(s) for s in ev.scans.values()))
    patches, not_proposed = [], []
    for f in sorted(findings, key=lambda f: f["id"]):
        meta = rules[f["rule_id"]]
        base = {"finding_id": f["id"], "rule_id": f["rule_id"], "resource_id": f["resource_id"]}
        if f["status"] == "excepted":
            not_proposed.append({**base, "reason": f"finding is excepted by {f['exception_id']}"})
            continue
        if meta["remediation"]["kind"] != "auto":
            not_proposed.append({**base, "reason": "manual remediation: " + meta["remediation"]["guidance"]})
            continue
        try:
            ops_by_file = STRATEGIES[f["rule_id"]](by_res[f["resource_id"]], by_key[(f["rule_id"], f["resource_id"])],
                                                   docs, context)
            ops_by_file = {k: v for k, v in ops_by_file.items() if v}
            if not ops_by_file:
                raise NotProposed("the strategy produced no change")
            for file in ops_by_file:
                if canonical_text(docs[file]) != originals[file]:
                    raise NotProposed(f"{file} is not in canonical form, so a minimal diff cannot be produced")
        except NotProposed as exc:
            not_proposed.append({**base, "reason": str(exc)})
            continue
        patches.append({**base, "strategy": meta["remediation"]["strategy"], "ops": ops_by_file})

    accepted_texts: dict[str, str] = {}
    out = []
    with tempfile.TemporaryDirectory() as tmp:
        for n, p in enumerate(patches, start=1):
            pid = f"P-{n:02d}"
            texts = {file: canonical_text(apply_patch(docs[file], ops)) for file, ops in p["ops"].items()}
            diff = "".join(unified_diff(file, originals[file], texts[file]) for file in sorted(texts))
            entry = {"id": pid, **{k: p[k] for k in ("finding_id", "rule_id", "resource_id", "strategy")},
                     "files": sorted(texts), "json_patch": [{"file": f, "ops": p["ops"][f]} for f in sorted(p["ops"])]}
            blocked = _publish_problems(originals, texts, diff, sensitive)
            if blocked:
                out.append({**entry, "status": "withheld", "diff": None, "json_patch": None, "regression": None,
                            "reason": "the diff would publish sensitive raw content or could not be verified as text ("
                                      + "; ".join(blocked) + "); apply the change by hand"})
                continue
            copy_dir = _patched_copy(snapshot_dir, name, Path(tmp) / pid, texts)
            after = evaluate(copy_dir, manifest, context, tools)
            patched = {f: [op["path"] for op in ops] for f, ops in p["ops"].items()}
            reg = compare(ev, after, {(p["rule_id"], p["resource_id"])}, rule_ids, patched, requested)
            if reg["ok"]:
                out.append({**entry, "status": "accepted", "diff": diff, "regression": reg,
                            "reason": "target finding resolves to pass; no other rule result, finding or resource "
                                      "changes"})
            else:
                out.append({**entry, "status": "rejected", "diff": None, "regression": reg,
                            "reason": "; ".join(reg["reasons"])})
        accepted = [e for e, p in zip(out, patches, strict=True) if e["status"] == "accepted"]
        combined = None
        if accepted:
            merged: dict[str, Any] = {}
            for e, p in zip(out, patches, strict=True):
                if e["status"] != "accepted":
                    continue
                for file, ops in p["ops"].items():
                    merged[file] = apply_patch(merged.get(file, docs[file]), ops)
            accepted_texts = {f: canonical_text(d) for f, d in merged.items()}
            copy_dir = _patched_copy(snapshot_dir, name, Path(tmp) / "combined", accepted_texts)
            after = evaluate(copy_dir, manifest, context, tools)
            patched = {}
            for e in accepted:
                for block in e["json_patch"]:
                    patched.setdefault(block["file"], []).extend(op["path"] for op in block["ops"])
            reg = compare(ev, after, {(e["rule_id"], e["resource_id"]) for e in accepted}, rule_ids, patched,
                          requested)
            combined_diff = "".join(unified_diff(f, originals[f], accepted_texts[f]) for f in sorted(accepted_texts))
            leaked = _publish_problems(originals, accepted_texts, combined_diff, sensitive)
            combined = {"patch_file": "remediation.patch", "patch_ids": [e["id"] for e in accepted],
                        "files": sorted(accepted_texts), "regression": reg,
                        "ok": reg["ok"] and not leaked, "withheld_reason": "; ".join(leaked) or None,
                        "diff": combined_diff if reg["ok"] and not leaked else ""}
    counts = {s: sum(e["status"] == s for e in out) for s in ("accepted", "rejected", "withheld")}
    return {"mode": "propose", "explanation": (
        "Each auto-remediable active finding gets a JSON Patch against its raw snapshot file. The patch is applied "
        "to a temporary copy of the snapshot and the whole evaluation is re-run; it is accepted only when the "
        "targeted finding resolves to pass and nothing else changes. remediation.patch combines the accepted "
        "patches (one diff per file, re-verified together) and applies from the repository root. The committed "
        "snapshot is never modified."),
        "patches": out, "not_proposed": not_proposed, "combined": combined,
        "counts": {**counts, "proposed": len(out), "not_proposed": len(not_proposed)}}


def not_requested() -> dict[str, Any]:
    return {"mode": "none", "explanation": "Remediation was not requested (remediation: none); no patches were "
            "generated or verified and no remediation.patch was written.",
            "patches": [], "not_proposed": [], "combined": None,
            "counts": {"accepted": 0, "rejected": 0, "withheld": 0, "proposed": 0, "not_proposed": 0}}
