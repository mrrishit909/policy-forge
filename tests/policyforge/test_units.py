"""Focused unit tests: scanner, redaction, references, exceptions, CIDR/port logic, patches, CLI, repo hygiene."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys

import pytest

from policyforge import outputs, pipeline, redact, remediate
from policyforge.jsonpos import Scan, pointer, resolve, split_pointer
from tests.policyforge.conftest import ROOT, SNAPSHOTS

# ------------------------------------------------------------------ line-number scanner
DOC = """{
  "a": [
    1,
    {"b~c/d": "x\\"y"},
    [true, null]
  ],
  "e": {
    "f": -1.5e3
  }
}
"""


def test_scanner_lines_and_escaping():
    s = Scan(DOC)
    assert s.lines[""] == 1
    assert s.lines["/a"] == 2
    assert s.lines["/a/0"] == 3
    assert s.lines["/a/1/b~0c~1d"] == 4
    assert s.lines["/a/2/1"] == 5
    assert s.lines["/e/f"] == 8
    assert pointer(("b~c/d",)) == "/b~0c~1d" and split_pointer("/b~0c~1d") == ["b~c/d"]
    assert resolve(json.loads(DOC), "/a/1/b~0c~1d") == 'x"y'
    assert s.nearest_line("/e/missing/deeper") == 7
    assert [t.value for t in s.strings] == ['x"y']


@pytest.mark.parametrize("bad", ["{", '{"a" 1}', "[1,]", "{} x", '{"a": tru}'])
def test_scanner_rejects_invalid_json(bad):
    with pytest.raises(ValueError):
        Scan(bad)


def test_scanner_matches_every_value_of_real_snapshots():
    for snap in SNAPSHOTS:
        for f in (ROOT / "snapshots" / snap).glob("*.json"):
            text = f.read_text()
            s = Scan(text)
            lines = text.splitlines()
            doc = json.loads(text)
            for ptr, line in s.lines.items():
                value = resolve(doc, ptr)
                if isinstance(value, (str, int, float, bool)) and ptr:
                    assert json.dumps(value, ensure_ascii=False) in lines[line - 1], (f.name, ptr)


# ------------------------------------------------------------------ redaction
def test_redact_tree_drops_names_and_masks_values():
    canary = "pf-canary-" + "ab" * 8 + "-not-a-secret"
    clean, records = redact.redact_tree({"tags": {"owner": "a", "note": f"x {canary}", "db_password": "zz"},
                                         "list": [{"connectionString": "y"}]}, "/properties")
    assert clean == {"tags": {"owner": "a", "note": redact.MASK}, "list": [{}]}
    assert records == [
        {"path": "/properties/tags/note", "reason": "sensitive-value", "action": "masked"},
        {"path": "/properties/tags/db_password", "reason": "sensitive-name", "action": "dropped"},
        {"path": "/properties/list/0/connectionString", "reason": "sensitive-name", "action": "dropped"},
    ]
    assert canary not in json.dumps(clean) and "zz" not in json.dumps(clean)


def test_redacted_text_preserves_lines_and_masks_inherited_values():
    canary = "pf-canary-" + "cd" * 8 + "-not-a-secret"
    text = json.dumps({"Name": "ok", "OSProfile": {"AdminPassword": canary},
                       "Env": {"Variables": {"DB_CONNECTION_STRING": f"Server=s;Password={canary};"}},
                       "UserData": {"Value": "inner"}}, indent=2) + "\n"
    s = Scan(text)
    out = redact.redacted_text(s)
    assert len(out.splitlines()) == len(text.splitlines())
    assert canary not in out and "inner" not in out and '"ok"' in out
    assert out.count('"[redacted]"') == 3
    assert canary in redact.sensitive_values(s)
    assert redact.leaks(f"context {canary}", set()) and not redact.leaks("clean text", {canary})


# ------------------------------------------------------------------ references
def _res(rid, provider, refs=()):
    return {"id": rid, "provider": provider, "refs": [{"kind": k, "target": t} for k, t in refs]}


def test_resolve_refs_normalized_native_case_and_unresolved():
    inv = [
        _res("aws:storage_bucket:logs", "aws"),
        _res("aws:unsupported:arn:aws:iam::1:group/ops", "aws"),
        _res("aws:iam_user:u", "aws", [("delivers", "aws:storage_bucket:logs"), ("member_of", "arn:aws:iam::1:group/ops"),
                                       ("member_of", "arn:aws:iam::1:group/missing")]),
        _res("azure:network_security_group:/subscriptions/S/NSG", "azure"),
        _res("azure:compute_instance:/subscriptions/S/VM", "azure",
             [("uses_network_group", "azure:network_security_group:/subscriptions/s/nsg")]),
    ]
    edges, unresolved = pipeline.resolve_refs(inv)
    assert {"from": "aws:iam_user:u", "to": "aws:storage_bucket:logs", "kind": "delivers"} in edges
    assert {"from": "aws:iam_user:u", "to": "aws:unsupported:arn:aws:iam::1:group/ops", "kind": "member_of"} in edges
    assert {"from": "azure:compute_instance:/subscriptions/S/VM", "to": "azure:network_security_group:/subscriptions/S/NSG",
            "kind": "uses_network_group"} in edges
    assert unresolved == [{"from": "aws:iam_user:u", "kind": "member_of", "target": "arn:aws:iam::1:group/missing"}]


# ------------------------------------------------------------------ exceptions
def _exc(eid, created, expires):
    return {"id": eid, "rule_id": "PF-NET-001", "resource_id": "aws:security_group:sg-1", "reason": "r", "owner": "o",
            "ticket": "t", "created": created, "expires": expires}


def test_exception_states_on_edge_dates():
    reg = {"exceptions": [_exc("E1", "2026-10-01", "2026-10-21"), _exc("E2", "2026-09-01", "2026-10-20"),
                          _exc("E3", "2026-10-22", "2026-11-01"), _exc("E4", "2026-10-21", "2026-10-30"),
                          _exc("E5", "2026-10-01", "2027-06-01")]}
    hygiene = {"failures": ["E5: expiry is more than 90 days after created"],
               "failure_details": [{"msg": "E5: expiry is more than 90 days after created", "index": 4,
                                    "reason": "expiry is more than 90 days after created"}]}
    out = {e["id"]: e for e in pipeline.evaluate_exceptions(
        reg, hygiene, "2026-10-21", {"PF-NET-001"}, {("PF-NET-001", "aws:security_group:sg-1")},
        {"aws:security_group:sg-1"})}
    assert out["E1"]["state"] == "active"  # expires exactly on as_of: still active (inclusive)
    assert out["E2"]["state"] == "expired"  # expired the day before as_of
    assert out["E3"]["state"] == "not_yet_active"
    assert out["E4"]["state"] == "active"  # created exactly on as_of
    assert out["E5"]["state"] == "rejected" and out["E5"]["problems"] == ["expiry is more than 90 days after created"]
    assert out["E1"]["effect"] == "excepts the matching finding"


def test_exception_registry_hygiene_with_conftest(tmp_path):
    hygiene = pipeline.conftest_check(pipeline.Tools(), "registry",
                                      json.loads((ROOT / "exceptions" / "registry.json").read_text()), tmp_path)
    rejected = {m.split(":", 1)[0] for m in hygiene["failures"]}
    assert rejected == {"EXC-003", "EXC-004", "EXC-006", "EXC-007"}


# ------------------------------------------------------------------ CIDR / port boundaries (Rego library)
def _opa(query: str):
    proc = subprocess.run([shutil.which("opa"), "eval", "--v1-compatible", "--format", "json", "-d", "policy/rules",
                           query], cwd=ROOT, capture_output=True, text=True, check=True)
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


def test_internet_wide_cidr_boundaries():
    cases = {"0.0.0.0/0": True, "0.0.0.0/1": True, "128.0.0.0/1": True, "11.0.0.0/8": True, "11.0.0.0/9": False,
             "10.0.0.0/8": False, "203.0.113.0/24": False, "203.0.113.5": False, "::/0": True, "2000::/3": True,
             "2001:db8::/32": False, "fc00::/7": False, "not-a-cidr": False}
    got = _opa("[c | some c in " + json.dumps(list(cases)) + "; data.policyforge.lib.wide_cidr(c)]")
    assert sorted(got) == sorted(c for c, wide in cases.items() if wide)


def test_port_range_boundaries():
    entries = {"20-22": [20, 22], "23-25": [23, 25], "22-22": [22, 22], "0-65535": [0, 65535]}
    q = ("[k | some k, r in " + json.dumps(entries)
         + '; data.policyforge.lib.covers({"port_from": r[0], "port_to": r[1]}, 22)]')
    assert sorted(_opa(q)) == ["0-65535", "20-22", "22-22"]


# ------------------------------------------------------------------ patches
def test_apply_patch_operations():
    doc = {"a": {"b": False}, "l": [1, 2]}
    out = remediate.apply_patch(doc, [{"op": "test", "path": "/a/b", "value": False},
                                      {"op": "replace", "path": "/a/b", "value": True},
                                      {"op": "add", "path": "/l/-", "value": 3},
                                      {"op": "add", "path": "/a/c", "value": {"x": 1}},
                                      {"op": "remove", "path": "/l/0"}])
    assert out == {"a": {"b": True, "c": {"x": 1}}, "l": [2, 3]} and doc == {"a": {"b": False}, "l": [1, 2]}
    with pytest.raises(ValueError):
        remediate.apply_patch(doc, [{"op": "test", "path": "/a/b", "value": True}])
    with pytest.raises(ValueError):
        remediate.apply_patch(doc, [{"op": "replace", "path": "/a/zz", "value": 1}])


def test_unified_diff_applies_with_patch(tmp_path):
    before = remediate.canonical_text({"a": [1, 2, 3], "b": {"c": False}})
    after = remediate.canonical_text({"a": [1, 2, 3], "b": {"c": True}})
    rel = "snapshots/x/f.json"
    (tmp_path / "snapshots" / "x").mkdir(parents=True)
    (tmp_path / rel).write_text(before)
    diff = remediate.unified_diff(rel, before, after)
    assert diff.startswith(f"diff --git a/{rel} b/{rel}\n--- a/{rel}\n+++ b/{rel}\n@@")
    subprocess.run([shutil.which("patch"), "-p1", "-F0"], input=diff, text=True, cwd=tmp_path, check=True,
                   capture_output=True)
    assert (tmp_path / rel).read_text() == after


def test_snapshots_are_canonical_and_synthetic():
    for snap in SNAPSHOTS:
        d = ROOT / "snapshots" / snap
        manifest = json.loads((d / "manifest.json").read_text())
        assert manifest["synthetic"] is True and manifest["name"] == snap
        assert sorted(manifest["files"] + ["manifest.json", "context.json"]) == sorted(p.name for p in d.iterdir())
        total = 0
        for f in d.glob("*.json"):
            text = f.read_text()
            total += len(text.encode())
            assert remediate.canonical_text(json.loads(text)) == text, f"{f} is not in canonical form"
        assert total < 150_000


def test_withheld_when_diff_context_is_sensitive():
    canary = "pf-canary-" + "ef" * 8 + "-not-a-secret"
    before = remediate.canonical_text({"flag": False, "AdminPassword": canary})
    after = remediate.canonical_text({"flag": True, "AdminPassword": canary})
    diff = remediate.unified_diff("snapshots/x/f.json", before, after)
    assert redact.leaks(diff, {canary}), "the guard must catch sensitive diff context"


# ------------------------------------------------------------------ request validation and CLI
def test_request_problems_pack_order():
    ok = {"snapshot": "aws-baseline-2026-10", "rule_packs": ["storage", "audit"], "remediation": "none",
          "as_of": "2026-10-21"}
    assert pipeline.request_problems(ok) == []
    assert pipeline.request_problems({**ok, "rule_packs": ["audit", "storage"]})
    assert pipeline.schema_problems({**ok, "rule_packs": ["dns"]})


def _cli(*args, cwd=ROOT):
    return subprocess.run([sys.executable, "-m", "policyforge", *args], cwd=cwd, capture_output=True, text=True)


def test_cli_exit_codes(tmp_path):
    req = tmp_path / "req.json"
    req.write_text(json.dumps({"snapshot": "aws-baseline-2026-10", "rule_packs": ["network", "audit"],
                               "remediation": "none", "as_of": "2026-10-21"}))
    out = tmp_path / "out"
    proc = _cli("run", "--request", str(req), "--out", str(out))
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["complete_coverage"] is False
    assert outputs.validate(out) == []
    assert not (out / "remediation.patch").exists()
    assert json.loads((out / "remediation.json").read_text())["mode"] == "none"
    # Output directory not empty -> bad input.
    assert _cli("run", "--request", str(req), "--out", str(out)).returncode == 2
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"snapshot": "aws-baseline-2026-10", "rule_packs": ["audit", "network"],
                               "remediation": "none", "as_of": "2026-10-21"}))
    assert _cli("run", "--request", str(bad), "--out", str(tmp_path / "o2")).returncode == 2
    bad.write_text(json.dumps({"snapshot": "prod-account", "rule_packs": ["audit"], "remediation": "none",
                               "as_of": "2026-10-21"}))
    assert _cli("run", "--request", str(bad), "--out", str(tmp_path / "o3")).returncode == 2
    bad.write_text("{not json")
    assert _cli("run", "--request", str(bad), "--out", str(tmp_path / "o4")).returncode == 2


def test_validate_detects_tampering(tmp_path):
    out = tmp_path / "out"
    pipeline.run({"snapshot": "aws-baseline-2026-10", "rule_packs": ["audit"], "remediation": "none",
                  "as_of": "2026-10-21"}, out)
    assert outputs.validate(out) == []
    s = json.loads((out / "summary.json").read_text())
    s["complete_coverage"] = True
    (out / "summary.json").write_text(json.dumps(s))
    problems = outputs.validate(out)
    assert any("complete_coverage" in p for p in problems) and any("hash mismatch" in p for p in problems)


# ------------------------------------------------------------------ repository hygiene
WRITTEN = ["adapters", "policy", "src", "snapshots", "exceptions", "schemas/inventory.schema.json",
           "schemas/outputs.schema.json", "tests/policyforge", "tests/bats", "tests/pester", "scripts/shell_checks.sh"]


def _written_files():
    for entry in WRITTEN:
        p = ROOT / entry
        yield from ([p] if p.is_file() else sorted(x for x in p.rglob("*") if x.is_file() and "__pycache__" not in x.parts))


def test_written_files_are_ascii_without_secret_patterns():
    sys.path.insert(0, str(ROOT / "scripts"))
    from secret_scan import scan_text

    for f in _written_files():
        text = f.read_text()
        assert text.isascii(), f"{f} contains non-ASCII characters"
        assert scan_text(str(f.relative_to(ROOT)), text) == [], f


def test_catalog_entries_are_complete():
    for rule in json.loads((ROOT / "policy" / "catalog.json").read_text())["rules"]:
        assert rule["does_not_evaluate"], rule["id"]
        assert rule["remediation"]["kind"] in {"auto", "manual"}
        key = "strategy" if rule["remediation"]["kind"] == "auto" else "guidance"
        assert rule["remediation"][key], rule["id"]


# ------------------------------------------------------------------ one sensitive-name rule in four implementations
def _examples():
    return json.loads((ROOT / "policy" / "sensitive-names.json").read_text())["sensitive_names"]["examples"]


def test_sensitive_name_rule_matches_examples_in_python_jq_and_rego():
    ex = _examples()
    assert [k for k in ex["sensitive"] if not redact.sensitive_name(k)] == []
    assert [k for k in ex["not_sensitive"] if redact.sensitive_name(k)] == []
    names = ex["sensitive"] + ex["not_sensitive"]
    jq = subprocess.run([shutil.which("jq"), "-n", "-c", "-L", "adapters/aws", "--slurpfile", "v",
                         "policy/sensitive-names.json", "--argjson", "names", json.dumps(names),
                         'include "names"; [$names[] | sensitive_name($v[0].sensitive_names)]'],
                        cwd=ROOT, capture_output=True, text=True, check=True)
    assert json.loads(jq.stdout) == [redact.sensitive_name(k) for k in names]
    rego = _opa_conftest("[k | some k in data.sensitive_names.examples.sensitive; not data.main.sensitive_key(k)]")
    assert rego == []
    rego = _opa_conftest("[k | some k in data.sensitive_names.examples.not_sensitive; data.main.sensitive_key(k)]")
    assert rego == []


def _opa_conftest(query: str):
    proc = subprocess.run([shutil.which("opa"), "eval", "--v1-compatible", "--format", "json", "-d", "policy/conftest",
                           "-d", "policy/sensitive-names.json", query], cwd=ROOT, capture_output=True, text=True,
                          check=True)
    return json.loads(proc.stdout)["result"][0]["expressions"][0]["value"]


def test_redaction_rules_for_siblings_nested_json_and_scalars():
    canary = "pf-canary-" + "12" * 8 + "-not-a-secret"
    text = json.dumps({
        "Tags": [{"Key": "db_password", "Value": "short"}, {"Key": "env", "Value": "prod"}],
        "Param": {"Name": "/prod/app/api-key", "Value": {"v": 7}},
        "Env": {"APP_CONFIG": json.dumps({"nested": {"client_secret": canary}})},
        "DeliveryToken": 4821739265, "TokenEndpoint": "https://login.example.invalid/token",
    }, indent=2) + "\n"
    a = redact.analyse(Scan(text))
    masked = {t.path for t in a.masked}
    assert ("Tags", 0, "Value") in masked and ("Tags", 1, "Value") not in masked
    assert ("Param", "Value", "v") in masked and ("DeliveryToken",) in masked and ("TokenEndpoint",) not in masked
    assert ("Env", "APP_CONFIG") in masked
    assert {canary, "4821739265", "short"} <= set(a.known)
    out = redact.redacted_text(Scan(text))
    assert canary not in out and "4821739265" not in out and "short" not in out and "login.example.invalid" in out
    clean, records = redact.redact_tree({"tags": [{"Key": "db_password", "Value": "x"}],
                                         "cfg": json.dumps({"password": "y"})})
    assert clean == {"tags": [{"Key": "db_password"}], "cfg": redact.MASK}
    assert [r["reason"] for r in records] == ["sensitive-name", "sensitive-value"]


def test_diff_guard_blocks_short_sensitive_context_and_apply_unified_is_strict():
    before = remediate.canonical_text({"IsLogging": False, "DeliveryToken": "Zq7!x", "Name": "t"})
    after = remediate.canonical_text({"IsLogging": True, "DeliveryToken": "Zq7!x", "Name": "t"})
    assert remediate.diff_guard("snapshots/x/f.json", before, after) == ["snapshots/x/f.json line 3",
                                                                          "snapshots/x/f.json new line 3"]
    sep = chr(0x2028)
    before = remediate.canonical_text({"a": False, "d": f"one{sep}two", "b": 1})
    after = remediate.canonical_text({"a": True, "d": f"one{sep}two", "b": 1})
    diff = remediate.unified_diff("snapshots/x/f.json", before, after)
    assert remediate.apply_unified({"snapshots/x/f.json": before}, diff) == {"snapshots/x/f.json": after}
    with pytest.raises(ValueError):
        remediate.apply_unified({"snapshots/x/f.json": before.replace('"b": 1', '"b": 2')}, diff)
