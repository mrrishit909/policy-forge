/* Maps the engine's output files (schemas/outputs.schema.json) onto the site's RunModel. */
import type {
  CheckResult, CheckStatus, EvidenceItem, ExceptionEntry, Pack, Patch, RegressionCheck, Resource, Rule, RuleTest, RunModel,
  Severity, SourceRef, Summary,
} from "./model";

/* eslint-disable @typescript-eslint/no-explicit-any */
export interface RawRun {
  run: any;
  manifest: any;
  summary: any;
  coverage: any;
  findings: any;
  inventory: any;
  relationships: any;
  exceptions: any;
  rule_tests: any;
  remediation: any;
  catalog: any;
}

const arr = <T = any>(x: unknown): T[] => (Array.isArray(x) ? (x as T[]) : []);

export function valueText(v: unknown): string {
  if (v === null || v === undefined) return "none";
  if (typeof v === "string") return v;
  // Spaced JSON so long values wrap between tokens rather than inside them.
  return JSON.stringify(v, null, 1).replace(/\n\s*/g, " ");
}

function source(s: any): SourceRef | null {
  if (!s || typeof s.file !== "string") return null;
  const ex = s.excerpt;
  return {
    file: s.file,
    pointer: String(s.pointer ?? ""),
    line: typeof s.line === "number" ? s.line : null,
    excerpt: ex && Array.isArray(ex.lines)
      ? { firstLine: Number(ex.first_line ?? 1), lines: ex.lines.map(String), cited: arr<number>(ex.cited_lines).map(Number) }
      : null,
  };
}

const evidence = (e: unknown): EvidenceItem[] => arr<any>(e).map((x) => ({ path: String(x.path ?? ""), value: valueText(x.value) }));

export const resultId = (ruleId: string, resourceId: string) => `${ruleId}::${resourceId}`;

/** "PF-AUD-001: fail to pass" for each targeted result of a patch. */
function targetText(t: any[]): string {
  return t.map((x) => `${x.rule_id} ${x.before} to ${x.after}`).join("; ");
}

export function regressionChecks(reg: any): RegressionCheck[] {
  if (!reg) return [];
  const targets = arr<any>(reg.targets);
  return [
    { label: "Targeted finding resolved", passed: targets.length > 0 && targets.every((t) => t.before === "fail" && t.after === "pass"), detail: targetText(targets) },
    { label: "Every other rule result unchanged", passed: arr(reg.changed_results).length === 0, detail: `${reg.checked_results ?? 0} results compared${arr(reg.changed_results).length ? `; ${arr(reg.changed_results).length} changed` : ""}` },
    { label: "Every other finding unchanged", passed: arr(reg.changed_findings).length === 0, detail: arr(reg.changed_findings).length ? `${arr(reg.changed_findings).length} changed` : "" },
    { label: "No other resource changed", passed: arr(reg.changed_resources).length === 0, detail: `${reg.checked_resources ?? 0} resources compared` },
  ];
}

export function adapt(raw: RawRun, base: string): RunModel {
  const cov = raw.coverage;
  const rulesMeta = new Map<string, any>(arr<any>(cov.rules).map((r) => [r.rule_id, r]));
  const findings = new Map<string, any>(arr<any>(raw.findings?.findings).map((f) => [resultId(f.rule_id, f.resource_id), f]));
  const results: CheckResult[] = arr<any>(cov.results).map((r) => {
    const id = resultId(r.rule_id, r.resource_id);
    const f = findings.get(id);
    const meta = rulesMeta.get(r.rule_id) ?? {};
    const status: CheckStatus = r.status === "fail" ? (f?.status === "excepted" ? "excepted" : "fail") : r.status === "unknown" ? "unknown" : "pass";
    return {
      id,
      ruleId: String(r.rule_id),
      pack: (meta.pack ?? f?.pack ?? "storage") as Pack,
      resourceId: String(r.resource_id),
      status,
      reason: String(f?.reason ?? r.reason ?? ""),
      evidence: evidence(f?.evidence ?? r.evidence),
      source: source(f?.source ?? r.source),
      severity: (meta.severity ?? f?.severity ?? "low") as Severity,
      exceptionId: f?.exception_id ?? null,
    };
  });

  const edges = arr<any>(raw.relationships?.edges);
  const redactions = arr<any>(raw.inventory?.redactions);
  const resources: Resource[] = arr<any>(raw.inventory?.resources).map((r) => ({
    id: String(r.id),
    name: String(r.name ?? r.id),
    type: String(r.type),
    nativeType: String(r.native_type ?? ""),
    provider: String(r.provider ?? ""),
    region: String(r.region ?? ""),
    supported: r.type !== "unsupported",
    source: source(r.source) ?? { file: "", pointer: "", line: null, excerpt: null },
    properties: (r.properties ?? {}) as Record<string, unknown>,
    relations: [
      ...edges.filter((e) => e.from === r.id).map((e) => ({ kind: String(e.kind), other: String(e.to), direction: "out" as const })),
      ...edges.filter((e) => e.to === r.id).map((e) => ({ kind: String(e.kind), other: String(e.from), direction: "in" as const })),
    ],
    redacted: redactions.filter((x) => x.resource_id === r.id).map((x) => String(x.path)),
  }));

  const rules: Rule[] = arr<any>(raw.catalog?.rules).map((r) => ({
    id: String(r.id),
    pack: r.pack as Pack,
    title: String(r.title),
    severity: r.severity as Severity,
    providers: arr<string>(r.providers),
    resourceTypes: arr<string>(r.resource_types),
    checks: String(r.checks ?? ""),
    notEvaluated: arr<string>(r.does_not_evaluate),
    remediation: {
      kind: r.remediation?.kind === "auto" ? "auto" : "manual",
      detail: [r.remediation?.strategy ?? r.remediation?.guidance, r.remediation?.caveat].filter(Boolean).join(" "),
    },
  }));

  const ruleTests: RuleTest[] = [];
  for (const r of arr<any>(raw.rule_tests?.rules)) {
    for (const kind of ["positive", "negative", "boundary"] as const) {
      const k = r.kinds?.[kind];
      if (!k) continue;
      const files = arr<string>(k.files);
      for (const file of files.length ? files : Array.from({ length: Number(k.fixtures ?? 0) }, (_, i) => `${kind}-${i + 1}`)) {
        ruleTests.push({ ruleId: String(r.rule_id), kind, name: `${r.rule_id}/${file}`, passed: Boolean(k.passed) });
      }
    }
  }
  for (const t of arr<any>(raw.rule_tests?.other_tests)) ruleTests.push({ ruleId: "", kind: "other", name: String(t.name), passed: Boolean(t.passed) });

  const exceptions: ExceptionEntry[] = arr<any>(raw.exceptions?.entries).map((e) => ({
    id: String(e.id), ruleId: String(e.rule_id ?? ""), resourceId: String(e.resource_id ?? ""), reason: String(e.reason ?? ""),
    owner: String(e.owner ?? ""), ticket: String(e.ticket ?? ""), created: String(e.created ?? ""), expires: String(e.expires ?? ""),
    state: (["active", "expired", "rejected", "not_yet_active"].includes(e.state) ? e.state : "rejected") as ExceptionEntry["state"],
    problems: arr<string>(e.problems).map(String), effect: String(e.effect ?? ""), inScope: Boolean(e.in_scope), matchesFailing: Boolean(e.matches_failing_result),
  }));

  const rem = raw.remediation ?? {};
  const patches: Patch[] = arr<any>(rem.patches).map((p) => ({
    id: String(p.id),
    resultId: p.finding_id ? String(p.finding_id) : null,
    ruleId: String(p.rule_id),
    resourceId: String(p.resource_id),
    file: arr<string>(p.files)[0] ?? "",
    state: (p.status === "accepted" ? "accepted" : p.status === "withheld" ? "withheld" : "rejected") as Patch["state"],
    reason: String(p.reason ?? ""),
    strategy: String(p.strategy ?? ""),
    diff: typeof p.diff === "string" ? p.diff : "",
    regression: regressionChecks(p.regression),
  }));

  const s = raw.summary;
  const unsupported = arr<any>(cov.unsupported).map((u) => `${u.name} (${u.native_type})`);
  const notEvaluated = arr<any>(cov.resources).filter((r) => r.status === "not_evaluated").map((r) => `${r.name} (${r.native_type}, no applicable rule)`);
  const summary: Summary = {
    evaluated: Number(s.checks?.evaluated ?? 0),
    passed: Number(s.checks?.passed ?? 0),
    failed: Number(s.findings?.active ?? 0),
    unknown: Number(s.checks?.unknown ?? 0),
    excepted: Number(s.findings?.excepted ?? 0),
    typesPresent: arr<string>(s.resource_types?.present),
    typesCovered: arr<string>(s.resource_types?.covered),
    uncoveredTypes: [...new Set(arr<any>(cov.unsupported).map((u) => String(u.native_type)))],
    uncovered: [...unsupported, ...notEvaluated],
    resourcesPresent: Number(s.resources?.present ?? 0),
    resourcesEvaluated: Number(s.resources?.evaluated ?? 0),
    coverageStatement: String(s.coverage_statement ?? ""),
    completeCoverage: Boolean(s.complete_coverage),
  };

  const run = raw.run;
  const m = raw.manifest;
  return {
    record: {
      runId: String(run.run_id), status: String(run.status), attempt: Number(run.attempt ?? 1), createdAt: String(run.created_at),
      completedAt: run.completed_at ? String(run.completed_at) : null, sourceCommit: String(run.source_commit ?? ""),
      workflowRunId: run.workflow_run_id ?? null, inputManifestHash: run.input_manifest_hash ?? m.input_manifest_hash ?? null,
      requestSource: { type: String(run.request_source?.type ?? "manual"), issue: run.request_source?.issue_number ?? null, actor: run.request_source?.actor ?? null },
    },
    params: { snapshot: m.params.snapshot, rulePacks: m.params.rule_packs, remediation: m.params.remediation, asOf: m.params.as_of },
    provider: String(s.provider ?? m.snapshot?.provider ?? ""),
    summary,
    results,
    resources,
    rules,
    ruleTests,
    exceptions,
    patches,
    remediationRequested: rem.mode === "propose",
    tools: (m.tools ?? {}) as Record<string, string>,
    packageVersion: String(m.package_version ?? ""),
    patchUrl: rem.combined?.ok && patches.some((p) => p.state === "accepted") ? `${base}remediation.patch` : null,
    reportUrl: `${base}report.md`,
  };
}
