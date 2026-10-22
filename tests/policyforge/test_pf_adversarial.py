"""Independent adversarial verification of Policy Forge's security and correctness claims.

Each confirmed defect (PF-01..PF-18) has one focused test. They were added as strict xfails and the markers were
removed as each defect was fixed, so every test here is now a plain regression test.
Preconditions use `require` (pytest.fail), which is not an AssertionError, so a broken precondition shows up as a
real failure instead of hiding behind the xfail. Tests without an xfail mark are regression guards for claims that
held. Crafted snapshots live in a private copy of the repository tree (pipeline.ROOT and outputs.ROOT are
monkeypatched to it); committed files are never modified. None of these tests is a release gate.
"""

from __future__ import annotations

import copy
import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any

import pytest

from policyforge import outputs, pipeline, remediate
from tests.policyforge.conftest import ROOT, SNAPSHOTS, full_request, load

PACKS = ["storage", "iam", "network", "audit", "relationships"]
AS_OF = "2026-10-21"
SUB = "/subscriptions/00000000-0000-4000-8000-000000000001"
OWNER_ROLE = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"
ALL_USERS = "http://acs.amazonaws.com/groups/global/AllUsers"
LINE_SEP = chr(0x2028)  # U+2028 LINE SEPARATOR


def require(cond: Any, msg: str) -> None:
    """Precondition: fails the test outright (pytest.fail is not an AssertionError, so no xfail can absorb it)."""
    if not cond:
        pytest.fail(f"precondition broken: {msg}")


@dataclass
class Forge:
    """A private copy of the repository tree that pipeline.ROOT points at for one test."""

    root: Path
    work: Path

    def path(self, snap: str, file: str) -> Path:
        return self.root / "snapshots" / snap / file

    def load(self, snap: str, file: str) -> Any:
        return json.loads(self.path(snap, file).read_text())

    def save(self, snap: str, file: str, doc: Any) -> None:
        self.path(snap, file).write_text(remediate.canonical_text(doc))

    def evaluate(self, snap: str) -> pipeline.Evaluation:
        d = self.root / "snapshots" / snap
        return pipeline.evaluate(d, json.loads((d / "manifest.json").read_text()),
                                 json.loads((d / "context.json").read_text()), pipeline.Tools())

    def run(self, snap: str, packs=PACKS, remediation: str = "none", as_of: str = AS_OF) -> Path:
        out = self.work / f"out-{len(list(self.work.glob('out-*')))}"
        pipeline.run({"snapshot": snap, "rule_packs": packs, "remediation": remediation, "as_of": as_of}, out)
        return out


@pytest.fixture
def forge(tmp_path, monkeypatch, stub_log) -> Forge:
    root = tmp_path / "repo"
    for d in ("adapters", "policy", "schemas", "exceptions", "snapshots"):
        shutil.copytree(ROOT / d, root / d)
    monkeypatch.setattr(pipeline, "ROOT", root)
    monkeypatch.setattr(outputs, "ROOT", root)
    return Forge(root, tmp_path)


def statuses(ev: pipeline.Evaluation) -> dict[tuple[str, str], str]:
    return {(r["rule_id"], r["resource_id"]): r["status"] for r in ev.results}


def texts(out: Path) -> dict[str, str]:
    return {p.name: p.read_text() for p in sorted(out.iterdir())}


def published_in(out: Path | None, needle: str) -> list[str]:
    return [] if out is None else [name for name, text in texts(out).items() if needle in text]


def run_or_refuse(f: Forge, snap: str, **kw) -> Path | None:
    """A run that refuses to publish (OutputError) counts as not publishing."""
    try:
        return f.run(snap, **kw)
    except pipeline.OutputError:
        return None


# ------------------------------------------------------------------ crafted resource builders
def aws_user(iam: dict, name: str, document: dict) -> dict:
    u = copy.deepcopy(iam["UserDetailList"][0])
    u.update(UserName=name, Arn=f"arn:aws:iam::111122223333:user/{name}", UserId=f"AIDAPFEXAMPLE{len(name):04d}",
             GroupList=[], AttachedManagedPolicies=[], UserPolicyList=[{"PolicyName": "inline", "PolicyDocument": document}])
    u.pop("AccessKeys", None)
    return u


def add_aws_user(f: Forge, name: str, statement: dict) -> str:
    snap = "aws-drifted-2026-10"
    iam = f.load(snap, "iam-account-authorization-details.json")
    iam["UserDetailList"].append(aws_user(iam, name, {"Version": "2012-10-17", "Statement": [statement]}))
    f.save(snap, "iam-account-authorization-details.json", iam)
    return f"aws:iam_user:arn:aws:iam::111122223333:user/{name}"


def add_azure_role(f: Forge, role_id: str, actions: list[str], scopes: list[str]) -> None:
    snap = "azure-lab-2026-10"
    roles = f.load(snap, "Get-AzRoleDefinition.json")
    r = copy.deepcopy(next(x for x in roles if x["IsCustom"]))
    r.update(Name=f"Role {role_id}", Id=role_id, Actions=actions, NotActions=[], AssignableScopes=scopes)
    roles.append(r)
    f.save(snap, "Get-AzRoleDefinition.json", roles)


def add_azure_assignment(f: Forge, name: str, role_id: str, scope: str | None) -> str:
    snap = "azure-lab-2026-10"
    items = f.load(snap, "Get-AzRoleAssignment.json")
    a = copy.deepcopy(items[1])
    rid = f"{SUB}/providers/Microsoft.Authorization/roleAssignments/{name}"
    a.update(RoleAssignmentName=name, RoleAssignmentId=rid, RoleDefinitionId=role_id, RoleDefinitionName=f"Role {role_id}",
             ObjectId=f"obj-{name}", SignInName=f"{name}@fernhollow.example", DisplayName=name, Scope=scope)
    if scope is None:
        a.pop("Scope")
    items.append(a)
    f.save(snap, "Get-AzRoleAssignment.json", items)
    return f"azure:role_assignment:{rid}"


def add_nsg(f: Forge, name: str, rules: list[dict]) -> str:
    snap = "azure-lab-2026-10"
    nsgs = f.load(snap, "Get-AzNetworkSecurityGroup.json")
    n = copy.deepcopy(nsgs[0])
    n["Name"] = name
    n["Id"] = n["Id"].rsplit("/", 1)[0] + "/" + name
    template = n["SecurityRules"][0]
    n["SecurityRules"] = []
    for i, spec in enumerate(rules):
        r = copy.deepcopy(template)
        r.update(Name=f"rule-{i}", Id=f"{n['Id']}/securityRules/rule-{i}", **spec)
        n["SecurityRules"].append(r)
    nsgs.append(n)
    f.save(snap, "Get-AzNetworkSecurityGroup.json", nsgs)
    return f"azure:network_security_group:{n['Id']}"


def add_bucket(f: Forge, snap: str, name: str, **fields) -> str:
    s3 = f.load(snap, "s3-buckets.json")
    b = copy.deepcopy(s3["Buckets"][0])
    b["Name"] = name
    b.update(fields)
    s3["Buckets"].append(b)
    f.save(snap, "s3-buckets.json", s3)
    return f"aws:storage_bucket:{name}"


def add_sg(f: Forge, gid: str, perms: list[dict]) -> str:
    snap = "aws-drifted-2026-10"
    doc = f.load(snap, "ec2-describe-security-groups.json")
    g = copy.deepcopy(doc["SecurityGroups"][0])
    g.update(GroupId=gid, GroupName=gid, IpPermissions=perms)
    doc["SecurityGroups"].append(g)
    f.save(snap, "ec2-describe-security-groups.json", doc)
    return f"aws:security_group:{gid}"


def perm(proto, port, v4=(), v6=()) -> dict:
    p = {"IpProtocol": proto, "IpRanges": [{"CidrIp": c} for c in v4], "Ipv6Ranges": [{"CidrIpv6": c} for c in v6],
         "PrefixListIds": [], "UserIdGroupPairs": []}
    if port is not None:
        p.update(FromPort=port, ToPort=port)
    return p


def public_policy_bucket_fields(statement: dict) -> dict:
    return {"GetBucketPolicy": {"Policy": json.dumps({"Version": "2012-10-17", "Statement": [statement]})},
            "GetPublicAccessBlock": {"PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False}},
            "GetBucketLogging": {}}


# ================================================================== claim 1: sensitive configuration
def test_pf01_sensitive_keyed_tag_value_not_in_excerpts(forge):
    snap, planted = "aws-drifted-2026-10", "Tr0ub4dor-and-3-horse"
    rid = add_bucket(forge, snap, "fh-tagged-public", GetBucketPolicy=None, GetPublicAccessBlock=None,
                     GetBucketLogging={}, GetBucketTagging={"TagSet": [{"Key": "db_password", "Value": planted}]})
    s3 = forge.load(snap, "s3-buckets.json")
    s3["Buckets"][-1]["GetBucketAcl"]["Grants"].append({"Grantee": {"Type": "Group", "URI": ALL_USERS},
                                                         "Permission": "READ"})
    forge.save(snap, "s3-buckets.json", s3)
    out = run_or_refuse(forge, snap)
    require(out is not None and load(out, "checks.json")["passed"], "the run publishes (a refusal would hide the fix)")
    res = next(r for r in load(out, "inventory.json")["resources"] if r["id"] == rid)
    require(res["properties"]["tags"] == {}, "the adapter itself treats the tag as sensitive and drops it")
    assert published_in(out, planted) == []
    assert any('"Value": "[redacted]"' in line for f in load(out, "findings.json")["findings"]
               for line in f["source"]["excerpt"]["lines"])


def test_pf02_sensitive_member_inside_json_string_not_published(forge):
    snap, planted = "aws-drifted-2026-10", "nested-json-hunter2-value"
    lam = forge.load(snap, "lambda-list-functions.json")
    lam["Functions"][1]["Environment"]["Variables"]["APP_CONFIG"] = json.dumps({"db_password": planted})
    forge.save(snap, "lambda-list-functions.json", lam)
    out = run_or_refuse(forge, snap)
    require(out is not None and load(out, "checks.json")["passed"], "the run publishes (a refusal would hide the fix)")
    assert published_in(out, planted) == []
    assert any('"APP_CONFIG": "[redacted]"' in line for u in load(out, "coverage.json")["unsupported"]
               for line in u["source"]["excerpt"]["lines"])


def _trail_status_member(f: Forge, key: str, value: Any) -> None:
    """Insert key: value right after IsLogging in the org-management-trail status (the PF-AUD-001 target)."""
    snap = "aws-drifted-2026-10"
    doc = f.load(snap, "cloudtrail-get-trail-status.json")
    for i, st in enumerate(doc["TrailStatus"]):
        if st["Name"] == "org-management-trail":
            items = list(st.items())
            at = [k for k, _ in items].index("IsLogging") + 1
            doc["TrailStatus"][i] = dict(items[:at] + [(key, value)] + items[at:])
    f.save(snap, "cloudtrail-get-trail-status.json", doc)


def test_pf03_short_sensitive_value_not_in_patch_context(forge):
    _trail_status_member(forge, "DeliveryToken", "Zq7!x")
    out = run_or_refuse(forge, "aws-drifted-2026-10", remediation="propose")
    require(out is not None and load(out, "checks.json")["passed"], "the run publishes (a refusal would hide the fix)")
    # Excerpts mask sensitive names at any length, so only the patch diff context can carry the value.
    assert published_in(out, "Zq7!x") == []
    entry = next(p for p in load(out, "remediation.json")["patches"] if p["rule_id"] == "PF-AUD-001")
    assert entry["status"] == "withheld" and entry["diff"] is None and "cloudtrail-get-trail-status.json line" in \
        entry["reason"]


def test_pf04_non_string_sensitive_value_not_in_excerpts(forge):
    _trail_status_member(forge, "DeliveryToken", 4821739265)
    out = run_or_refuse(forge, "aws-drifted-2026-10")
    require(out is not None and load(out, "checks.json")["passed"], "the run publishes (a refusal would hide the fix)")
    assert published_in(out, "4821739265") == []
    assert any('"DeliveryToken": "[redacted]"' in line for f in load(out, "findings.json")["findings"]
               for line in f["source"]["excerpt"]["lines"])


# ================================================================== claim 3: unknown, never pass
def test_pf07_management_group_assignable_wildcard_role_is_admin(forge):
    mg = "/providers/Microsoft.Management/managementGroups/fh-root"
    add_azure_role(forge, "role-mg-star", ["*"], [mg])
    rid = add_azure_assignment(forge, "asg-mg-star", "role-mg-star", SUB)
    got = statuses(forge.evaluate("azure-lab-2026-10"))
    require(("PF-IAM-003", rid) in got, "the assignment is evaluated")
    assert got[("PF-IAM-003", rid)] != "pass"


def test_pf08_admin_action_matching_ignores_case(forge):
    rid = add_aws_user(forge, "eve.upper", {"Effect": "Allow", "Action": "IAM:*", "Resource": "*"})
    got = statuses(forge.evaluate("aws-drifted-2026-10"))
    require(got[("PF-IAM-002", rid)] == "fail", "PF-IAM-002 does recognise 'IAM:*' as a service wildcard")
    assert got[("PF-IAM-003", rid)] != "pass"


def test_pf09_partial_wildcard_admin_action_not_pass(forge):
    add_azure_role(forge, "role-ra-star", ["Microsoft.Authorization/roleAssignments/*"], [SUB])
    rid = add_azure_assignment(forge, "asg-ra-star", "role-ra-star", SUB)
    got = statuses(forge.evaluate("azure-lab-2026-10"))
    assert got[("PF-IAM-003", rid)] != "pass"


def test_pf10_partial_deny_does_not_shadow_internet_allow(forge):
    nsg = add_nsg(forge, "nsg-deny-one-host", [
        {"Access": "Deny", "Priority": 100, "Protocol": "Tcp", "SourceAddressPrefix": ["*"],
         "DestinationPortRange": ["22"], "DestinationAddressPrefix": ["10.0.0.5/32"]},
        {"Access": "Allow", "Priority": 200, "Protocol": "Tcp", "SourceAddressPrefix": ["Internet"],
         "DestinationPortRange": ["22"], "DestinationAddressPrefix": ["*"]},
    ])
    got = statuses(forge.evaluate("azure-lab-2026-10"))
    assert got[("PF-NET-001", nsg)] != "pass"


def test_pf11_wildcard_resource_arn_not_pass(forge):
    rid = add_aws_user(forge, "eve.arnstar", {"Effect": "Allow", "Action": "*", "Resource": "arn:aws:*:*:*:*"})
    got = statuses(forge.evaluate("aws-drifted-2026-10"))
    assert got[("PF-IAM-001", rid)] != "pass"


def _pf12_unparsed_principal(f: Forge) -> tuple[str, tuple[str, str]]:
    rid = add_bucket(f, "aws-drifted-2026-10", "fh-principal-list", **public_policy_bucket_fields(
        {"Effect": "Allow", "Principal": ["*"], "Action": "s3:GetObject", "Resource": "*"}))
    return "aws-drifted-2026-10", ("PF-STOR-002", rid)


def _pf12_effect_spelling(f: Forge) -> tuple[str, tuple[str, str]]:
    rid = add_bucket(f, "aws-drifted-2026-10", "fh-effect-lower", **public_policy_bucket_fields(
        {"Effect": "allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}))
    return "aws-drifted-2026-10", ("PF-STOR-002", rid)


def _pf12_missing_scope(f: Forge) -> tuple[str, tuple[str, str]]:
    return "azure-lab-2026-10", ("PF-IAM-003", add_azure_assignment(f, "asg-no-scope", OWNER_ROLE, None))


def _pf12_missing_ports(f: Forge) -> tuple[str, tuple[str, str]]:
    nsg = add_nsg(f, "nsg-no-ports", [{"Access": "Allow", "Priority": 200, "Protocol": "Tcp",
                                       "SourceAddressPrefix": ["Internet"]}])
    nsgs = f.load("azure-lab-2026-10", "Get-AzNetworkSecurityGroup.json")
    del nsgs[-1]["SecurityRules"][0]["DestinationPortRange"]
    f.save("azure-lab-2026-10", "Get-AzNetworkSecurityGroup.json", nsgs)
    return "azure-lab-2026-10", ("PF-NET-001", nsg)


@pytest.mark.parametrize("build", [
    pytest.param(_pf12_unparsed_principal, id="principal-list"),
    pytest.param(_pf12_effect_spelling, id="effect-not-exact"),
    pytest.param(_pf12_missing_scope, id="assignment-without-scope"),
    pytest.param(_pf12_missing_ports, id="nsg-rule-without-ports"),
])
def test_pf12_unreadable_input_is_unknown_not_pass(forge, build):
    snap, key = build(forge)
    got = statuses(forge.evaluate(snap))
    require(key in got, f"{key} is evaluated")
    assert got[key] != "pass"


# ================================================================== claim 4: patches
def _apply_entry(src_dir: Path, dest_dir: Path, entry: dict) -> None:
    shutil.copytree(src_dir, dest_dir)
    for block in entry["json_patch"]:
        p = dest_dir / block["file"].split("/", 2)[2]
        p.write_text(remediate.canonical_text(remediate.apply_patch(json.loads(p.read_text()), block["ops"])))


def test_pf14_accepted_patch_changes_no_rule_outside_the_request(stub_log, tmp_path):
    """PF-14 (strengthened once fixed): a narrow request still compares every rule for the provider, so the
    STOR-002 patch on fh-audit-logs is rejected because it flips PF-REL-002, and every patch the narrow run does
    accept changes no rule result at all when re-checked independently."""
    snap = "aws-drifted-2026-10"
    out = tmp_path / "storage-only"
    pipeline.run({"snapshot": snap, "rule_packs": ["storage"], "remediation": "propose", "as_of": AS_OF}, out)
    rem = load(out, "remediation.json")
    entry = next((p for p in rem["patches"] if p["rule_id"] == "PF-STOR-002"
                  and p["resource_id"] == "aws:storage_bucket:fh-audit-logs"), None)
    require(entry is not None, "the narrow request still proposes the STOR-002 patch on fh-audit-logs")
    assert entry["status"] == "rejected" and entry["diff"] is None
    assert "PF-REL-002" in entry["reason"] and "outside the requested packs" in entry["reason"]
    assert entry["id"] not in (rem["combined"] or {}).get("patch_ids", [])
    accepted = [p for p in rem["patches"] if p["status"] == "accepted"]
    require(accepted, "the narrow request still accepts some patch")
    src = ROOT / "snapshots" / snap
    manifest, context = load(src, "manifest.json"), load(src, "context.json")
    before = statuses(pipeline.evaluate(src, manifest, context, pipeline.Tools()))
    for n, e in enumerate(accepted):
        _apply_entry(src, tmp_path / f"patched-{n}" / snap, e)
        after = statuses(pipeline.evaluate(tmp_path / f"patched-{n}" / snap, manifest, context, pipeline.Tools()))
        target = (e["rule_id"], e["resource_id"])
        changed = sorted(k for k in before if k != target and before[k] != after.get(k))
        assert changed == [], (e["id"], changed)


def test_pf13_unicode_line_separator_keeps_patch_and_excerpt_exact(forge, tmp_path):
    snap = "aws-drifted-2026-10"
    doc = forge.load(snap, "ec2-describe-security-groups.json")
    doc["SecurityGroups"][0]["Description"] = "Public web tier" + LINE_SEP + "(second line)"
    sg2 = next(g for g in doc["SecurityGroups"] if g["GroupId"] == "sg-0fe00000000000002")
    sg2["IpPermissions"][0]["IpRanges"][0]["Description"] = "Temporary vendor access" + LINE_SEP + "SEC-1061"
    forge.save(snap, "ec2-describe-security-groups.json", doc)
    out = forge.run(snap, remediation="propose")
    combined = load(out, "remediation.json")["combined"]
    require(combined and combined["ok"], "the engine reports the combined patch as verified")
    require(shutil.which("git"), "git is on PATH")
    problems = []
    g = tmp_path / "gitcheck"
    shutil.copytree(forge.root / "snapshots" / snap, g / "snapshots" / snap)
    subprocess.run(["git", "init", "-q"], cwd=g, check=True, capture_output=True)
    shutil.copy(out / "remediation.patch", g / "remediation.patch")
    proc = subprocess.run(["git", "apply", "--check", "remediation.patch"], cwd=g, capture_output=True, text=True)
    if proc.returncode != 0:
        problems.append(f"git apply --check: {proc.stderr.strip()}")
    raw = forge.path(snap, "ec2-describe-security-groups.json").read_text().split("\n")
    for f in load(out, "findings.json")["findings"]:
        src = f["source"]
        if src["file"].endswith("ec2-describe-security-groups.json"):
            shown = src["excerpt"]["lines"][src["line"] - src["excerpt"]["first_line"]]
            if shown != raw[src["line"] - 1]:
                problems.append(f"{f['id']}: line {src['line']} shows {shown.strip()!r}")
    assert problems == []


# ================================================================== claim 5: exceptions
def test_pf05_rejected_exception_never_applies(forge):
    reg = json.loads((forge.root / "exceptions" / "registry.json").read_text())
    e4 = next(e for e in reg["exceptions"] if e["id"] == "EXC-004")
    span = date.fromisoformat(e4["expires"]) - date.fromisoformat(e4["created"])
    require(span.days > 90, "the entry breaks the 90-day rule, so Conftest must reject it")
    e4["id"] = "EXC-004: vendor"
    (forge.root / "exceptions" / "registry.json").write_text(json.dumps(reg, indent=2) + "\n")
    out = forge.run("aws-drifted-2026-10", packs=["network"])
    finding = next(f for f in load(out, "findings.json")["findings"]
                   if f["id"] == "PF-NET-001::aws:security_group:sg-0fe00000000000002")
    assert finding["status"] == "active" and finding["exception_id"] is None


def test_pf18_exception_expired_before_capture_never_applies(stub_log, tmp_path):
    """PF-18 (rewritten once fixed): a run may not be backdated before the snapshot's capture date, so an exception
    that had already expired when the snapshot was captured cannot except a finding in it."""
    backdated = {"snapshot": "aws-drifted-2026-10", "rule_packs": ["network"], "remediation": "none",
                 "as_of": "2026-09-01"}
    assert any("earlier than the snapshot capture date" in p for p in pipeline.request_problems(backdated))
    with pytest.raises(pipeline.InputError, match="earlier than the snapshot capture date"):
        pipeline.run(backdated, tmp_path / "backdated")
    out = tmp_path / "at-capture"
    pipeline.run({**backdated, "as_of": "2026-10-19"}, out)
    captured = date.fromisoformat(load(out, "manifest.json")["snapshot"]["captured_at"][:10])
    entries = {e["id"]: e for e in load(out, "exceptions.json")["entries"]}
    stale = [f["id"] for f in load(out, "findings.json")["findings"] if f["exception_id"]
             and date.fromisoformat(entries[f["exception_id"]]["expires"]) < captured]
    assert stale == []
    assert entries["EXC-002"]["state"] == "expired"


# ================================================================== claim 6: coverage
def test_pf06_unevaluated_resources_make_coverage_partial(forge):
    snap = "aws-baseline-2026-10"
    m = forge.load(snap, "manifest.json")
    m["files"].remove("lambda-list-functions.json")
    forge.save(snap, "manifest.json", m)
    forge.path(snap, "lambda-list-functions.json").unlink()
    iam = forge.load(snap, "iam-account-authorization-details.json")
    iam["GroupDetailList"] = []
    for u in iam["UserDetailList"]:
        u["GroupList"] = []
    forge.save(snap, "iam-account-authorization-details.json", iam)
    out = forge.run(snap)
    s = load(out, "summary.json")
    require(s["resources"]["not_evaluated"] > 0, "some resources had no applicable rule")
    assert s["complete_coverage"] is False and "partial" in s["coverage_statement"]


# ================================================================== loud failures and request handling
def _tag_bucket(f: Forge, value: str) -> None:
    s3 = f.load("aws-baseline-2026-10", "s3-buckets.json")
    s3["Buckets"][0]["GetBucketTagging"]["TagSet"].append({"Key": "note", "Value": value})
    f.save("aws-baseline-2026-10", "s3-buckets.json", s3)


@pytest.mark.parametrize("value", [
    pytest.param("pci non-compliant until Q4", id="banned-word-in-data"),
    pytest.param("snapshots/daily#3", id="raw-location-lookalike"),
])
def test_pf16_benign_snapshot_strings_do_not_abort_the_run(forge, value):
    _tag_bucket(forge, value)
    out = forge.run("aws-baseline-2026-10")
    assert load(out, "checks.json")["passed"]


def test_pf17_impossible_as_of_is_an_input_error(stub_log, tmp_path):
    with pytest.raises(pipeline.InputError):
        pipeline.run({"snapshot": "aws-baseline-2026-10", "rule_packs": ["audit"], "remediation": "none",
                      "as_of": "2026-02-30"}, tmp_path / "out")


# ================================================================== claim 2: no execution, no escape
def test_pf15_symlinked_snapshot_file_is_refused(forge, tmp_path):
    snap = "aws-baseline-2026-10"
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps({"Items": [{"Name": "outside-marker-5150"}]}, indent=2) + "\n")
    m = forge.load(snap, "manifest.json")
    m["files"].append("extra.json")
    forge.save(snap, "manifest.json", m)
    os.symlink(outside, forge.path(snap, "extra.json"))
    try:
        out = forge.run(snap)
    except pipeline.InputError:
        out = None
    assert published_in(out, "outside-marker-5150") == []


def test_guard_manifest_names_cannot_traverse(forge):
    for provider_snap in ("aws-baseline-2026-10", "azure-lab-2026-10"):
        m = forge.load(provider_snap, "manifest.json")
        m["files"].append("../aws-drifted-2026-10/manifest.json")
        forge.save(provider_snap, "manifest.json", m)
        with pytest.raises(pipeline.InputError, match="plain file name"):
            forge.run(provider_snap)


def test_guard_snapshot_strings_are_data_not_code(forge, tmp_path):
    marker = tmp_path / "PWNED"
    payloads = [f"$(touch {marker})", f"`touch {marker}`", f"; touch {marker}", f"\"; touch {marker}; echo \"",
                "$(env)", "$env:PATH", "@(Invoke-Expression 'touch x')", "\\(env)"]
    _tag_bucket(forge, " | ".join(payloads))
    vms = forge.load("azure-lab-2026-10", "Get-AzVM.json")
    vms[0]["Tags"]["note"] = " | ".join(payloads)
    vms[0]["Name"] = f"$(touch {marker})"
    forge.save("azure-lab-2026-10", "Get-AzVM.json", vms)
    for snap in ("aws-baseline-2026-10", "azure-lab-2026-10"):
        out = forge.run(snap)
        assert payloads[0] in (out / "inventory.json").read_text(), snap
    assert not marker.exists()


# ================================================================== regression guards for claims that held
def test_guard_rule_edge_cases_evaluate_conservatively(forge):
    """Spellings the adapters normalise correctly (claim 3 inputs that held)."""
    sg = {k: add_sg(forge, k, [p]) for k, p in {
        "sg-0000000000000ed01": perm("tcp", 22, ["0.0.0.0/00"]),
        "sg-0000000000000ed02": perm("tcp", 22, v6=["0::/0"]),
        "sg-0000000000000ed03": perm("all", None, ["0.0.0.0/0"]),
        "sg-0000000000000ed04": perm(-1, None, ["0.0.0.0/0"]),
        "sg-0000000000000ed05": perm("TCP", 22, ["0.0.0.0/0"]),
        "sg-0000000000000ed06": perm("tcp", 22, ["0.0.0.0/0 "]),
    }.items()}
    users = {
        "upper-s3": add_aws_user(forge, "edge.s3", {"Effect": "Allow", "Action": "S3:*", "Resource": "*"}),
        "cond-null": add_aws_user(forge, "edge.cond", {"Effect": "Allow", "Action": "*", "Resource": "*",
                                                        "Condition": None}),
    }
    bucket = add_bucket(forge, "aws-drifted-2026-10", "fh-edge-aws-list", **public_policy_bucket_fields(
        {"Effect": "Allow", "Principal": {"AWS": ["*"]}, "Action": "s3:GetObject", "Resource": "*"}))
    notp = add_bucket(forge, "aws-drifted-2026-10", "fh-edge-notprincipal", **public_policy_bucket_fields(
        {"Effect": "Allow", "NotPrincipal": {"AWS": "arn:aws:iam::111122223333:root"}, "Action": "s3:GetObject",
         "Resource": "*"}))
    got = statuses(forge.evaluate("aws-drifted-2026-10"))
    assert [got[("PF-NET-001", sg[k])] for k in sorted(sg)] == ["fail", "fail", "fail", "fail", "fail", "unknown"]
    assert got[("PF-IAM-002", users["upper-s3"])] == "fail"
    assert got[("PF-IAM-001", users["cond-null"])] == "unknown"
    assert got[("PF-STOR-002", bucket)] == "fail"
    assert got[("PF-STOR-002", notp)] == "unknown"
    tags = add_nsg(forge, "nsg-edge-tag-case", [{"Access": "Allow", "Priority": 200, "Protocol": "Tcp",
                                                 "SourceAddressPrefix": ["INTERNET"], "DestinationPortRange": ["22"]}])
    shadow = add_nsg(forge, "nsg-edge-low-prio-deny", [
        {"Access": "Deny", "Priority": 300, "Protocol": "*", "SourceAddressPrefix": ["*"], "DestinationPortRange": ["*"]},
        {"Access": "Allow", "Priority": 200, "Protocol": "Tcp", "SourceAddressPrefix": ["*"],
         "DestinationPortRange": ["22"]}])
    az = statuses(forge.evaluate("azure-lab-2026-10"))
    assert az[("PF-NET-001", tags)] == "unknown"
    assert az[("PF-NET-001", shadow)] == "fail"


def test_guard_exceptions_match_one_exact_rule_and_resource(stub_log, tmp_path):
    target = ("PF-NET-001", "aws:security_group:sg-0fe00000000000002")
    base = {"rule_id": target[0], "resource_id": target[1], "reason": "r", "owner": "o", "ticket": "t",
            "created": "2026-10-01", "expires": "2026-12-01"}
    variants = {
        "V-CASE": {"resource_id": target[1].upper()},
        "V-SPACE": {"resource_id": target[1] + " "},
        "V-LOOKALIKE": {"resource_id": target[1].replace("sg-", "sg" + chr(0x2010))},
        "V-PREFIX": {"resource_id": target[1][:-1]},
        "V-WILDCARD": {"resource_id": target[1][:-1] + "*"},
        "V-RULE-CASE": {"rule_id": target[0].lower()},
        "V-EXPIRED": {"created": "2026-09-01", "expires": "2026-10-20"},
        "V-FUTURE": {"created": "2026-10-22", "expires": "2026-11-01"},
        "V-LONG": {"expires": "2027-01-01"},
    }
    reg = {"exceptions": [{**base, "id": k, **v} for k, v in variants.items()]}
    hygiene = pipeline.conftest_check(pipeline.Tools(), "registry", reg, tmp_path)
    other = ("PF-NET-001", "aws:security_group:sg-0fe00000000000005")
    res = {e["id"]: e for e in pipeline.evaluate_exceptions(reg, hygiene, AS_OF, {"PF-NET-001"}, {target, other},
                                                             {target[1], other[1]})}
    applied = [k for k, e in res.items() if e["state"] == "active" and e["matches_failing_result"]]
    assert applied == []


def test_guard_committed_remediation_patches_apply_with_git(runs, tmp_path):
    require(shutil.which("git"), "git is on PATH")
    for snap, run_dir in runs.items():
        g = tmp_path / snap
        shutil.copytree(ROOT / "snapshots" / snap, g / "snapshots" / snap)
        subprocess.run(["git", "init", "-q"], cwd=g, check=True, capture_output=True)
        shutil.copy(run_dir / "remediation.patch", g / "remediation.patch")
        proc = subprocess.run(["git", "apply", "--check", "remediation.patch"], cwd=g, capture_output=True, text=True)
        assert proc.returncode == 0, (snap, proc.stderr)
        assert (run_dir / "remediation.patch").read_text().count("diff --git ") >= 1


def test_guard_byte_identical_under_other_hash_seed_and_cwd(runs, stub_log, tmp_path):
    snap = "azure-lab-2026-10"
    req = tmp_path / "req.json"
    req.write_text(json.dumps(full_request(snap)))
    other = tmp_path / "elsewhere"
    other.mkdir()
    env = {**os.environ, "PYTHONHASHSEED": "4242"}
    proc = subprocess.run([sys.executable, "-m", "policyforge", "run", "--request", str(req), "--out",
                           str(tmp_path / "out")], cwd=other, env=env, capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    first = sorted(p.name for p in runs[snap].iterdir())
    assert first == sorted(p.name for p in (tmp_path / "out").iterdir())
    for name in first:
        assert (runs[snap] / name).read_bytes() == (tmp_path / "out" / name).read_bytes(), name


def test_guard_no_cloud_cli_invoked_by_adversarial_runs(stub_log):
    """Last in this module: every crafted run above executed with the stub cloud CLIs first on PATH."""
    assert stub_log.read_text() == ""
    assert set(SNAPSHOTS) == {p.name for p in (ROOT / "snapshots").iterdir() if p.is_dir()}
