"""The eight hard release gates (marked `gate`). Each gate loops over snapshots internally."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from policyforge import pipeline
from tests.policyforge.conftest import ROOT, full_request, load

KINDS = ("positive", "negative", "boundary")
VOCAB = json.loads((ROOT / "policy" / "sensitive-names.json").read_text())["sensitive_names"]


def sensitive_key(name) -> bool:
    """Independent re-implementation of the documented word rule (policy/sensitive-names.json)."""
    if not isinstance(name, str):
        return False
    s = re.sub(r"([A-Za-z])([0-9])", r"\1_\2", re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2",
                                                     re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", name)))
    words = [w for w in re.split(r"[^a-z0-9]+", s.encode().lower().decode()) if w and not w.isdigit()]
    return bool(words) and (words[-1] in VOCAB["words"] or "_".join(words[-2:]) in VOCAB["pairs"])

CANARY = re.compile(r"pf-canary-[0-9a-f]+-not-a-secret")


def catalog():
    return json.loads((ROOT / "policy" / "catalog.json").read_text())["rules"]


def tool(name):
    path = shutil.which(name)
    assert path, f"{name} must be on PATH for the gate tests"
    return path


def manifest_of(snap):
    d = ROOT / "snapshots" / snap
    return d, json.loads((d / "manifest.json").read_text()), json.loads((d / "context.json").read_text())


@pytest.fixture(scope="session")
def patched(runs, stub_log, tmp_path_factory):
    """Each accepted patch applied with `patch -p1 -F0` (not the engine's own patcher) to a pristine copy of
    the snapshot, then re-evaluated. Keyed by (snapshot, patch id)."""
    out = {}
    patch_bin = tool("patch")
    for snap, run_dir in runs.items():
        src, manifest, context = manifest_of(snap)
        for p in load(run_dir, "remediation.json")["patches"]:
            if p["status"] != "accepted":
                continue
            root = tmp_path_factory.mktemp(f"{snap}-{p['id']}")
            shutil.copytree(src, root / "snapshots" / snap)
            subprocess.run([patch_bin, "-p1", "-F0", "--no-backup-if-mismatch"], input=p["diff"], text=True,
                           cwd=root, check=True, capture_output=True)
            ev = pipeline.evaluate(root / "snapshots" / snap, manifest, context, pipeline.Tools())
            out[(snap, p["id"])] = (p, ev)
    return out


@pytest.mark.gate
def test_gate1_fixtures_exist_and_opa_tests_pass():
    rules = catalog()
    validator = Draft202012Validator(json.loads((ROOT / "schemas" / "inventory.schema.json").read_text()))
    for rule in rules:
        d = ROOT / "policy" / "fixtures" / rule["id"]
        for kind in KINDS:
            files = sorted(d.glob(f"{kind}-*.json"))
            assert files, f"{rule['id']} has no {kind} fixture"
            assert sorted(rule["fixtures"][kind]) == [f"policy/fixtures/{rule['id']}/{f.name}" for f in files]
            for f in files:
                body = json.loads(f.read_text())
                assert list(body) == [f.stem], f"{f} must be keyed by its own stem"
                fx = body[f.stem]
                for res in fx["input"]["resources"]:
                    assert not list(validator.iter_errors(res)), f"{f}: {res['id']} is not a valid normalized resource"
                statuses = set(fx["expected"].values())
                assert statuses <= {"pass", "fail", "unknown"} and statuses
                if kind == "positive":
                    assert "fail" in statuses
                if kind == "negative":
                    assert statuses == {"pass"}
    proc = subprocess.run([tool("opa"), "test", "--v1-compatible", "--format", "json", "policy"], cwd=ROOT,
                          capture_output=True, text=True)
    tests = json.loads(proc.stdout)
    failed = [t["name"] for t in tests if t.get("fail") or t.get("error")]
    assert proc.returncode == 0 and not failed, failed
    names = {t["name"] for t in tests}
    for rule in rules:
        for kind in KINDS:
            assert f"test_{rule['id'].replace('-', '_')}_{kind}" in names
    ev = subprocess.run([tool("opa"), "eval", "--v1-compatible", "--format", "json", "-d", "policy/rules",
                         "data.policyforge.rule_ids"], cwd=ROOT, capture_output=True, text=True, check=True)
    rego_ids = json.loads(ev.stdout)["result"][0]["expressions"][0]["value"]
    assert sorted(rego_ids) == sorted(r["id"] for r in rules), "catalog and Rego rules must match one to one"


@pytest.mark.gate
def test_gate2_unsupported_and_unevaluable_are_unknown(runs):
    expected_unknown = {
        "aws-drifted-2026-10": [
            ("PF-STOR-002", "aws:storage_bucket:fh-shared-research"),  # Condition on Principal *
            ("PF-STOR-002", "aws:storage_bucket:fh-vendor-drop"),  # NotPrincipal
            ("PF-STOR-002", "aws:storage_bucket:fh-legacy-reports"),  # unparseable policy
            ("PF-IAM-001", "aws:iam_role:arn:aws:iam::111122223333:role/ops-automation-role"),  # NotAction
            ("PF-IAM-001", "aws:iam_role:arn:aws:iam::111122223333:role/scoped-admin-role"),  # Condition
            ("PF-NET-001", "aws:security_group:sg-0fe00000000000010"),  # ESP protocol
            ("PF-NET-002", "aws:security_group:sg-0fe00000000000009"),  # prefix list
        ],
        "azure-lab-2026-10": [
            ("PF-IAM-001", "azure:role_definition:00000000-0000-4000-9000-000000000903"),  # NotActions
            ("PF-AUD-004", "azure:diagnostic_setting:/subscriptions/00000000-0000-4000-8000-000000000001/resourceGroups/"
                           "rg-fh-lab/providers/Microsoft.KeyVault/vaults/kv-fh-lab/providers/microsoft.insights/"
                           "diagnosticSettings/kv-diagnostics"),
        ],
        "aws-baseline-2026-10": [("PF-IAM-003", "aws:iam_user:arn:aws:iam::111122223333:user/alice.ops")],
    }
    for snap, run_dir in runs.items():
        inv = load(run_dir, "inventory.json")["resources"]
        cov = load(run_dir, "coverage.json")
        unsupported = {r["id"] for r in inv if r["type"] == "unsupported"}
        assert unsupported, f"{snap} must contain unsupported resources"
        by_res = {r["id"]: r for r in cov["resources"]}
        for rid in unsupported:
            assert by_res[rid]["status"] == "unknown"
        assert {u["id"] for u in cov["unsupported"]} == unsupported
        assert all(u["status"] == "unknown" for u in cov["unsupported"])
        assert not [r for r in cov["results"] if r["resource_id"] in unsupported], "no rule may pass an unsupported type"
        assert all(r["status"] != "pass" for r in cov["resources"] if r["status"] == "not_evaluated")
        results = {(r["rule_id"], r["resource_id"]): r["status"] for r in cov["results"]}
        for key in expected_unknown[snap]:
            assert results[key] == "unknown", (snap, key, results.get(key))
        types = {t["type"]: t for t in cov["resource_types"]}
        assert types["unsupported"]["covered"] is False


@pytest.mark.gate
def test_gate3_accepted_patches_resolve_their_finding(runs, patched, evaluations, tmp_path):
    accepted_total = 0
    for snap, run_dir in runs.items():
        rem = load(run_dir, "remediation.json")
        findings = {f["id"]: f for f in load(run_dir, "findings.json")["findings"]}
        accepted = [p for p in rem["patches"] if p["status"] == "accepted"]
        accepted_total += len(accepted)
        for p in accepted:
            assert findings[p["finding_id"]]["status"] == "active"
            _, ev = patched[(snap, p["id"])]
            after = {(r["rule_id"], r["resource_id"]): r["status"] for r in ev.results}
            assert after[(p["rule_id"], p["resource_id"])] == "pass", (snap, p["id"])
            assert p["regression"]["targets"] == [{"rule_id": p["rule_id"], "resource_id": p["resource_id"],
                                                   "before": "fail", "after": "pass"}]
        for p in rem["patches"]:
            if p["status"] != "accepted":
                assert p["diff"] is None and p["reason"]
        # Every active auto-remediable finding was either patched or explicitly not proposed.
        handled = {p["finding_id"] for p in rem["patches"]} | {n["finding_id"] for n in rem["not_proposed"]}
        assert {f for f, v in findings.items() if v["status"] == "active"} <= handled
        # The combined remediation.patch applies to a pristine snapshot and resolves every accepted target.
        if accepted:
            combined = rem["combined"]
            assert combined["ok"] and combined["patch_ids"] == [p["id"] for p in accepted]
            src, manifest, context = manifest_of(snap)
            root = tmp_path / snap
            shutil.copytree(src, root / "snapshots" / snap)
            with (run_dir / "remediation.patch").open() as fh:
                subprocess.run([tool("patch"), "-p1", "-F0", "--no-backup-if-mismatch"], stdin=fh, cwd=root,
                               check=True, capture_output=True)
            ev = pipeline.evaluate(root / "snapshots" / snap, manifest, context, pipeline.Tools())
            targets = {(p["rule_id"], p["resource_id"]) for p in accepted}
            rule_ids = {r["rule_id"] for r in load(run_dir, "coverage.json")["results"]}
            before = {(r["rule_id"], r["resource_id"]): r["status"] for r in evaluations[snap].results
                      if r["rule_id"] in rule_ids}
            after = {(r["rule_id"], r["resource_id"]): r["status"] for r in ev.results if r["rule_id"] in rule_ids}
            assert set(after) == set(before)
            for key, status in before.items():
                assert after[key] == ("pass" if key in targets else status), (snap, key)
    assert accepted_total >= 10, "the snapshots are designed to produce accepted patches"


@pytest.mark.gate
def test_gate4_unrelated_behaviour_unchanged(runs, evaluations, patched):
    for (snap, pid), (p, after) in patched.items():
        before = evaluations[snap]
        rule_ids = {r["rule_id"] for r in load(runs[snap], "coverage.json")["results"]}
        b = {(r["rule_id"], r["resource_id"]): r for r in before.results if r["rule_id"] in rule_ids}
        a = {(r["rule_id"], r["resource_id"]): r for r in after.results if r["rule_id"] in rule_ids}
        assert set(a) == set(b), (snap, pid, "the set of evaluated results changed")
        target = (p["rule_id"], p["resource_id"])
        for key in b:
            if key == target:
                continue
            assert a[key]["status"] == b[key]["status"], (snap, pid, key)
            if b[key]["status"] == "fail":
                assert a[key]["evidence"] == b[key]["evidence"], (snap, pid, key)
        touched = set(p["regression"]["touched_resources"])
        assert touched == {p["resource_id"]}, (snap, pid, touched)  # each patch touches only its own resource
        ainv = {r["id"]: r for r in after.inventory}
        for r in before.inventory:
            if r["id"] in touched:
                continue
            x, y = json.loads(json.dumps(r)), json.loads(json.dumps(ainv[r["id"]]))
            x["source"].pop("line"), y["source"].pop("line")
            assert x == y, (snap, pid, r["id"])
    # Patches that would change other results are rejected with the reason, never offered.
    drifted = load(runs["aws-drifted-2026-10"], "remediation.json")
    rejected = {(p["rule_id"], p["resource_id"]): p for p in drifted["patches"] if p["status"] == "rejected"}
    assert ("PF-STOR-002", "aws:storage_bucket:fh-audit-logs") in rejected
    assert "PF-REL-002" in rejected[("PF-STOR-002", "aws:storage_bucket:fh-audit-logs")]["reason"]
    assert ("PF-NET-001", "aws:security_group:sg-0fe00000000000005") in rejected
    assert all(p["id"] not in drifted["combined"]["patch_ids"] for p in rejected.values())


CLOUD_PATTERNS = [
    re.compile(r"\b(aws|az|gcloud|terraform|kubectl|curl|wget)\s+-{0,2}[a-z]"),
    re.compile(r"\[\s*[\"'](aws|az|gcloud|terraform|kubectl|curl|wget)[\"']"),
    re.compile(r"(which|path)\(\s*[\"'](aws|az|gcloud|terraform|kubectl|curl|wget)[\"']"),
    re.compile(r"\b(Set|New|Remove|Update|Start|Stop)-Az[A-Za-z]+"),
    re.compile(r"\bInvoke-(WebRequest|RestMethod)\b|\bInvoke-Expression\b|\bStart-Process\b"),
    re.compile(r"\burllib\.request\b|\brequests\.(get|post|put)\b|\bsocket\.socket\b|\bhttp\.send\b"),
]
CODE_SUFFIXES = {".sh", ".jq", ".ps1", ".psm1", ".psd1", ".py", ".rego", ".bash"}


def strip_comments(path: Path) -> str:
    text = path.read_text()
    if path.suffix in {".ps1", ".psm1", ".psd1"}:
        text = re.sub(r"<#.*?#>", "", text, flags=re.S)
    if path.suffix == ".py":
        text = re.sub(r'"""[\s\S]*?"""', '""', text)
    return "\n".join(line.split("#", 1)[0] if not line.lstrip().startswith("#!") else "" for line in text.splitlines())


@pytest.mark.gate
def test_gate5_no_cloud_mutation_commands(runs, patched, stub_log):
    # Dynamic: the session ran every snapshot (remediation on, re-verification included) and every patched
    # re-evaluation with stub cloud CLIs first on PATH; none was ever invoked.
    assert runs and patched
    assert stub_log.read_text() == "", stub_log.read_text()
    for run_dir in runs.values():
        check = {c["id"]: c for c in load(run_dir, "checks.json")["checks"]}["no_cloud_command_invoked"]
        assert check["ok"]
        launched = set(check["detail"].split(": ", 1)[1].split(", "))
        assert launched <= {"bash", "pwsh", "opa", "conftest", "jq"}
    # Static: no cloud CLI or mutation call outside comments in adapters/, src/ or policy/.
    hits = []
    for top in ("adapters", "src", "policy"):
        for path in sorted((ROOT / top).rglob("*")):
            if path.is_file() and path.suffix in CODE_SUFFIXES:
                code = strip_comments(path)
                for pat in CLOUD_PATTERNS:
                    for m in pat.finditer(code):
                        hits.append(f"{path.relative_to(ROOT)}: {m.group(0)!r}")
    assert not hits, hits


def sensitive_raw_values(snapshot_dir: Path) -> set[str]:
    """Every planted canary, the value of every sensitive-named raw field, every Value of a Key/Name pair whose
    name is sensitive, and every sensitive member inside a JSON-encoded string. Each must hold a canary."""
    found: set[str] = set()

    def walk(node, hot, where):
        if isinstance(node, dict):
            name_key = next((k for k in node if k.lower() in VOCAB["name_members"]), None)
            pair = name_key is not None and sensitive_key(node[name_key])
            for k, v in node.items():
                walk(v, sensitive_key(k) or (pair and k.lower() in VOCAB["value_members"]), f"{where}/{k}")
        elif isinstance(node, list):
            for v in node:
                walk(v, hot, where)
        elif isinstance(node, str):
            if hot:
                assert CANARY.search(node), f"{snapshot_dir.name}: sensitive field {where} holds no canary"
                found.add(node)
            found.update(CANARY.findall(node))
            if node.strip()[:1] in "{[":
                try:
                    walk(json.loads(node), False, where + "(json)")
                except ValueError:
                    pass

    for f in sorted(snapshot_dir.glob("*.json")):
        walk(json.loads(f.read_text()), False, f.name)
    return found


@pytest.mark.gate
def test_gate6_sensitive_configuration_not_published(runs):
    redacted_lines, excerpt_text = 0, []
    for snap, run_dir in runs.items():
        values = sensitive_raw_values(ROOT / "snapshots" / snap)
        canaries = {v for v in values if CANARY.fullmatch(v)}
        assert len(canaries) >= 4, f"{snap} should plant several canaries"
        files = sorted(run_dir.iterdir())
        assert "remediation.patch" in {f.name for f in files}
        for f in files:
            text = f.read_text()
            leaked = [v for v in values if v in text]
            assert not leaked and not CANARY.search(text), f"{snap}/{f.name} publishes a sensitive raw value"
        # Second-layer redaction caught the canary hidden in a tag value with an innocuous key.
        inv = load(run_dir, "inventory.json")
        assert any(r["reason"] == "sensitive-value" for r in inv["redactions"]), snap
        # Every finding and unknown result carries a redacted excerpt (the excerpt itself was scanned above).
        cov = load(run_dir, "coverage.json")
        excerpts = [u["source"]["excerpt"] for u in cov["unsupported"]]
        excerpts += [r["source"]["excerpt"] for r in cov["results"] if r["status"] == "unknown"]
        redacted_lines += sum('"[redacted]"' in line for ex in excerpts for line in ex["lines"])
        excerpt_text += [line.strip() for ex in excerpts for line in ex["lines"]]
        for item in load(run_dir, "findings.json")["findings"] + [r for r in cov["results"] if r["status"] == "unknown"]:
            ex = item["source"]["excerpt"]
            assert ex["lines"] and set(ex["cited_lines"]) <= set(range(ex["first_line"], ex["first_line"] + len(ex["lines"])))
    assert redacted_lines > 0, "the excerpt redaction path must be exercised by the committed snapshots"
    # The committed drifted snapshot plants a Key/Value tag whose Key is sensitive and a secret inside a JSON-encoded
    # environment variable, both inside cited excerpt windows: each must be published only as "[redacted]".
    assert '"Value": "[redacted]"' in excerpt_text
    assert '"APP_CONFIG": "[redacted]",' in excerpt_text


BANNED = re.compile(r"(?i)compliant|compliance achieved")


@pytest.mark.gate
def test_gate7_partial_coverage_never_presented_as_complete(runs, stub_log, tmp_path):
    narrow = tmp_path / "narrow"
    summary = pipeline.run({"snapshot": "aws-baseline-2026-10", "rule_packs": ["audit"], "remediation": "none",
                            "as_of": "2026-10-21"}, narrow)
    dirs = {**runs, "narrow": narrow}
    for name, run_dir in dirs.items():
        s = load(run_dir, "summary.json")
        cov = load(run_dir, "coverage.json")
        t = cov["totals"]
        assert s["complete_coverage"] is False, name
        assert s["complete_coverage"] == (t["unknown"] == 0 and t["resources_unsupported"] == 0
                                          and t["resources_not_evaluated"] == 0
                                          and not s["resource_types"]["not_covered"])
        assert "partial" in s["coverage_statement"]
        assert "unknown" in s["coverage_statement"]
        assert s["checks"]["unknown"] == t["unknown"] and s["resources"]["unsupported"] == t["resources_unsupported"]
        for f in run_dir.iterdir():
            assert not BANNED.search(f.read_text()), f"{name}/{f.name}"
    assert summary["checks"]["unknown"] == 0
    assert "storage_bucket" in summary["resource_types"]["not_covered"]
    assert "not covered by the requested packs" in summary["coverage_statement"]


@pytest.mark.gate
def test_gate8_outputs_byte_identical_across_runs(runs, stub_log, tmp_path):
    for snap in ("aws-drifted-2026-10", "azure-lab-2026-10"):
        again = tmp_path / snap
        pipeline.run(full_request(snap), again)
        first = sorted(p.name for p in runs[snap].iterdir())
        assert first == sorted(p.name for p in again.iterdir())
        for name in first:
            assert (runs[snap] / name).read_bytes() == (again / name).read_bytes(), f"{snap}/{name} differs"
