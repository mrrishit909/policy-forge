"""CLI: python -m policyforge run --request REQUEST.json --out OUT_DIR

Exit codes: 0 success, 1 invalid outputs or a tool failure, 2 invalid request or bad input."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from policyforge import pipeline


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="policyforge", description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="evaluate one request")
    run.add_argument("--request", required=True, type=Path)
    run.add_argument("--out", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        params = json.loads(args.request.read_text())
    except (OSError, ValueError) as exc:
        print(f"policyforge: cannot read request: {exc}", file=sys.stderr)
        return 2
    try:
        summary = pipeline.run(params, args.out)
    except pipeline.InputError as exc:
        print(f"policyforge: invalid input: {exc}", file=sys.stderr)
        return 2
    except pipeline.OutputError as exc:
        print(f"policyforge: invalid outputs: {exc}", file=sys.stderr)
        return 1
    except RuntimeError as exc:
        print(f"policyforge: {exc}", file=sys.stderr)
        return 1
    print(json.dumps({k: summary[k] for k in ("snapshot", "checks", "findings", "complete_coverage",
                                              "coverage_statement")}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
