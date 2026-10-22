import { describe, expect, it } from "vitest";
import { parseUnifiedDiff } from "../../src/components/Code";
import { regressionChecks, resultId, valueText } from "../../src/data/adapter";
import { isStale, type Snapshot } from "../../src/data/site";
import { parseRoute, type Route, routeHref } from "../../src/routing";

describe("routing", () => {
  it("round-trips every route", () => {
    const routes: Route[] = [
      { view: "run", tab: "findings" },
      { view: "run", tab: "exceptions" },
      { view: "run", runId: "policy-forge-1", tab: "remediation" },
      { view: "history" },
      { view: "request" },
      { view: "about" },
    ];
    for (const r of routes) expect(parseRoute(routeHref(r))).toEqual(r);
  });
  it("falls back to findings for unknown paths and tabs", () => {
    expect(parseRoute("#/tab/nope")).toEqual({ view: "run", tab: "findings" });
    expect(parseRoute("#/whatever")).toEqual({ view: "run", tab: "findings" });
  });
});

describe("parseUnifiedDiff", () => {
  const patch = [
    "diff --git a/snapshots/x/a.json b/snapshots/x/a.json",
    "--- a/snapshots/x/a.json",
    "+++ b/snapshots/x/a.json",
    "@@ -1,3 +1,3 @@",
    " {",
    '-  "IsLogging": false',
    '+  "IsLogging": true',
    " }",
  ].join("\n");
  it("reads files, hunks, additions, removals and context", () => {
    const [f] = parseUnifiedDiff(patch);
    expect(f?.file).toBe("snapshots/x/a.json");
    expect(f?.lines.map((l) => l.kind)).toEqual(["hunk", "ctx", "del", "add", "ctx"]);
    expect(f?.lines[3]?.text).toBe('  "IsLogging": true');
  });
});

describe("adapter helpers", () => {
  it("formats evidence values without inventing text", () => {
    expect(valueText(null)).toBe("none");
    expect(valueText(false)).toBe("false");
    expect(valueText({ a: 1, b: [2] })).toBe('{ "a": 1, "b": [ 2 ] }');
  });
  it("ids results by rule and resource", () => {
    expect(resultId("PF-NET-001", "aws:security_group:sg-1")).toBe("PF-NET-001::aws:security_group:sg-1");
  });
  it("reports a patch's regression evidence honestly", () => {
    const ok = regressionChecks({ targets: [{ rule_id: "PF-AUD-001", before: "fail", after: "pass" }], changed_results: [], changed_findings: [], changed_resources: [], checked_results: 82, checked_resources: 45 });
    expect(ok.every((c) => c.passed)).toBe(true);
    const bad = regressionChecks({ targets: [{ rule_id: "PF-NET-001", before: "fail", after: "pass" }], changed_results: [{}], changed_findings: [], changed_resources: [], checked_results: 82, checked_resources: 45 });
    expect(bad.find((c) => c.label.startsWith("Every other rule result"))?.passed).toBe(false);
    expect(regressionChecks({ targets: [] })[0]?.passed).toBe(false);
  });
});

describe("staleness", () => {
  const snap: Snapshot = { project: "policy-forge", mode: "state-snapshot", generated_at: "2026-10-01T00:00:00Z", source_commit: "x", state_commit: "y", latest_run_id: "r", runs_included: ["r"], stale_after_hours: 336 };
  it("flags snapshots older than the window", () => {
    expect(isStale(snap, Date.parse("2026-10-10T00:00:00Z"))).toBe(false);
    expect(isStale(snap, Date.parse("2026-10-20T00:00:00Z"))).toBe(true);
  });
});
