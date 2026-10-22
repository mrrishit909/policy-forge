"""Shared fixtures: every snapshot's full request runs once per session with stub cloud CLIs first on PATH.

Gate tests fail (they do not skip) when opa, conftest, bash, jq or pwsh is missing.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from policyforge import pipeline

ROOT = Path(__file__).resolve().parents[2]
SNAPSHOTS = ["aws-baseline-2026-10", "aws-drifted-2026-10", "azure-lab-2026-10"]
PACKS = ["storage", "iam", "network", "audit", "relationships"]
STUBS = ["aws", "az", "gcloud", "terraform", "kubectl", "curl", "wget"]


def full_request(snapshot: str, remediation: str = "propose") -> dict:
    return {"snapshot": snapshot, "rule_packs": PACKS, "remediation": remediation, "as_of": "2026-10-21"}


def load(run_dir: Path, name: str):
    return json.loads((run_dir / name).read_text())


@pytest.fixture(scope="session")
def stub_log(tmp_path_factory) -> Path:
    """Directory of stub cloud CLIs that log their argv and exit 97, prepended to PATH for the whole session."""
    d = tmp_path_factory.mktemp("stubs")
    log = d / "invocations.log"
    log.write_text("")
    for name in STUBS:
        p = d / name
        p.write_text(f'#!/bin/sh\nprintf "%s %s\\n" "{name}" "$*" >> "{log}"\nexit 97\n')
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    old = os.environ["PATH"]
    os.environ["PATH"] = f"{d}{os.pathsep}{old}"
    yield log
    os.environ["PATH"] = old


@pytest.fixture(scope="session")
def runs(stub_log, tmp_path_factory) -> dict[str, Path]:
    out = {}
    for snap in SNAPSHOTS:
        d = tmp_path_factory.mktemp("run") / snap
        pipeline.run(full_request(snap), d)
        out[snap] = d
    return out


@pytest.fixture(scope="session")
def evaluations(stub_log) -> dict[str, pipeline.Evaluation]:
    """Unpatched evaluations of the committed snapshots."""
    out = {}
    for snap in SNAPSHOTS:
        d = ROOT / "snapshots" / snap
        out[snap] = pipeline.evaluate(d, json.loads((d / "manifest.json").read_text()),
                                      json.loads((d / "context.json").read_text()), pipeline.Tools())
    return out
