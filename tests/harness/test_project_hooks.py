"""Real hooks against real engine output (the fake-hook tests cannot catch contract drift)."""

import json
import shutil
from pathlib import Path

import project_hooks
from harness.memory import screen

REQUEST = {"snapshot": "aws-drifted-2026-10", "rule_packs": ["storage", "iam", "network", "audit", "relationships"],
           "remediation": "propose", "as_of": "2026-10-21"}


def test_hooks_on_real_outputs(tmp_path: Path):
    out = tmp_path / "out"
    project_hooks.compute(REQUEST, out)
    assert project_hooks.validate_outputs(out) == []

    summary = json.loads((out / "summary.json").read_text())
    line = project_hooks.headline(out)
    assert line.startswith(f"aws-drifted-2026-10 as of 2026-10-21: {summary['findings']['active']} failed, "
                           f"{summary['checks']['unknown']} not evaluated")
    assert "partial coverage" in line and "compliant" not in line.lower()

    state = tmp_path / "state"
    runs = []
    for i in range(3):
        rid = f"policy-forge-2026102{i}T000000Z-abcdef12-a1"
        shutil.copytree(out, state / "runs" / rid)
        runs.append({"run_id": rid, "status": "completed", "created_at": f"2026-10-2{i}T00:00:00Z"})
    (state / "index.json").write_text(json.dumps({"runs": runs}))
    candidates = project_hooks.memory_candidates(state)
    topics = {c["topic"] for c in candidates}
    assert any(t.endswith("fails repeatedly") for t in topics)
    assert any(t.endswith("often cannot be evaluated") for t in topics)
    for c in candidates:
        entry = {**c, "id": "mem-0123456789", "status": "active", "date": "2026-10-21", "supersedes": []}
        assert screen(entry) == [], (c["topic"], screen(entry))


def test_request_problems_canonical_pack_order():
    assert project_hooks.request_problems(REQUEST) == []
    assert project_hooks.request_problems({**REQUEST, "rule_packs": ["network", "storage"]})
