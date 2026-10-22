import { useEffect, useRef, useState } from "react";
import type { CheckResult, Resource, RunModel } from "../data/model";
import { typeLabel } from "../data/model";
import { routeHref } from "../routing";
import { CodeExcerpt, DiffView, parseUnifiedDiff } from "./Code";
import { Segmented } from "./Controls";
import { Icon } from "./Icon";
import { MarkGlyph } from "./Tally";

export type Selection = { kind: "result"; result: CheckResult } | { kind: "resource"; resource: Resource } | null;

const STATUS_TEXT = { pass: "Passed", fail: "Failed", unknown: "Could not be evaluated", excepted: "Excepted" } as const;

export function Severity({ level }: { level: string }) {
  const n = { critical: 4, high: 3, medium: 2, low: 1 }[level] ?? 0;
  return (
    <span className="pf-sev" data-level={level}>
      <i aria-hidden>{[1, 2, 3, 4].map((k) => <b key={k} data-on={k <= n} />)}</i>
      {level.charAt(0).toUpperCase() + level.slice(1)}
    </span>
  );
}

export function StatusMark({ status }: { status: CheckResult["status"] }) {
  return (
    <span className="pf-mark" data-s={status} role="img" aria-label={STATUS_TEXT[status]} style={{ cursor: "default" }}>
      <MarkGlyph status={status} />
    </span>
  );
}

function ResultBody({ r, run }: { r: CheckResult; run: RunModel }) {
  const rule = run.rules.find((x) => x.id === r.ruleId);
  const resource = run.resources.find((x) => x.id === r.resourceId);
  const exception = r.exceptionId ? run.exceptions.find((e) => e.id === r.exceptionId) : null;
  const patch = run.patches.find((p) => p.resultId === r.id || (p.ruleId === r.ruleId && p.resourceId === r.resourceId));
  const [mode, setMode] = useState<"diff" | "before" | "after">("diff");
  const diff = patch?.state === "accepted" ? parseUnifiedDiff(patch.diff)[0] : undefined;
  return (
    <>
      <div style={{ display: "grid", gap: 6 }}>
        <p className="pf-meta"><span className="pf-mono">{r.ruleId}</span> on {resource ? typeLabel(resource.type).toLowerCase() : "resource"}</p>
        <h2 className="pf-h2">{rule?.title ?? r.ruleId}</h2>
        <p className="pf-case-name pf-mono">{resource?.name ?? r.resourceId}</p>
      </div>
      <div className="pf-toolbar">
        <span style={{ display: "inline-flex", gap: 8, alignItems: "center" }}><StatusMark status={r.status} /> {STATUS_TEXT[r.status]}</span>
        <Severity level={r.severity} />
      </div>
      <p>{r.reason}</p>
      {exception && (
        <p className="pf-sheet-note">
          <span>Covered by exception <span className="pf-mono">{exception.id}</span> until {exception.expires} (owner {exception.owner}, {exception.ticket}). The finding stays listed.</span>
        </p>
      )}
      {r.evidence.length > 0 && (
        <dl className="pf-kv">
          {r.evidence.map((e) => (
            <div key={e.path} style={{ display: "contents" }}>
              <dt className="pf-mono">{e.path}</dt>
              <dd className="pf-mono">{e.value}</dd>
            </div>
          ))}
        </dl>
      )}
      {r.source?.excerpt ? (
        <CodeExcerpt
          file={r.source.file}
          lines={r.source.excerpt.lines}
          firstLine={r.source.excerpt.firstLine}
          cited={r.source.excerpt.cited}
          label={`Cited source, ${r.source.file} line ${r.source.line ?? ""}`}
        />
      ) : r.source ? (
        <p className="pf-cite">{r.source.file}{r.source.line ? `:${r.source.line}` : ""} <span className="pf-small">(pointer {r.source.pointer})</span></p>
      ) : null}
      {rule && rule.notEvaluated.length > 0 && (
        <div style={{ display: "grid", gap: 4 }}>
          <p className="pf-h3">What this rule does not evaluate</p>
          <ul style={{ paddingLeft: 18 }} className="pf-small">
            {rule.notEvaluated.map((n) => <li key={n}>{n}</li>)}
          </ul>
        </div>
      )}
      {patch && (
        <div style={{ display: "grid", gap: 8 }}>
          <p className="pf-h3">{patch.state === "accepted" ? "Verified patch" : patch.state === "withheld" ? "Patch withheld" : "Patch rejected"}</p>
          {diff ? (
            <>
              <Segmented label="Patch view" value={mode} onChange={setMode} options={[{ value: "diff", label: "Changes" }, { value: "before", label: "Before" }, { value: "after", label: "After" }]} />
              <DiffView diff={diff} mode={mode} />
            </>
          ) : (
            <p className="pf-small">{patch.reason}</p>
          )}
          <a href={routeHref({ view: "run", runId: run.record.runId, tab: "remediation" })}>Regression evidence for this patch</a>
        </div>
      )}
      {!patch && rule?.remediation.kind === "manual" && r.status === "fail" && (
        <p className="pf-small">No automatic patch: {rule.remediation.detail}</p>
      )}
    </>
  );
}

function ResourceBody({ res, run }: { res: Resource; run: RunModel }) {
  const results = run.results.filter((r) => r.resourceId === res.id);
  return (
    <>
      <div style={{ display: "grid", gap: 6 }}>
        <p className="pf-meta">{typeLabel(res.type)}, {res.provider.toUpperCase()}, {res.region || "no region"}</p>
        <h2 className="pf-h2 pf-wrap-anywhere">{res.name}</h2>
        <p className="pf-cite">{res.source.file}{res.source.line ? `:${res.source.line}` : ""}</p>
      </div>
      {!res.supported && (
        <p className="pf-sheet-note">No rule evaluates <span className="pf-mono">{res.nativeType}</span>. It is listed so the review does not imply it was checked.</p>
      )}
      {results.length > 0 && (
        <ul style={{ listStyle: "none", display: "grid", gap: 6 }} aria-label="Checks on this resource">
          {results.map((r) => (
            <li key={r.id} style={{ display: "grid", gridTemplateColumns: "auto minmax(0, 1fr)", gap: 10, alignItems: "start" }}>
              <StatusMark status={r.status} />
              <span><span className="pf-mono">{r.ruleId}</span> <span className="pf-small">{r.reason}</span></span>
            </li>
          ))}
        </ul>
      )}
      {res.relations.length > 0 && (
        <div style={{ display: "grid", gap: 4 }}>
          <p className="pf-h3">Relationships</p>
          <ul style={{ listStyle: "none", display: "grid", gap: 3 }} className="pf-small">
            {res.relations.map((rel, i) => {
              const other = run.resources.find((x) => x.id === rel.other);
              return <li key={i}>{rel.direction === "out" ? rel.kind.replace(/_/g, " ") : `${rel.kind.replace(/_/g, " ")} (from)`} <span className="pf-mono pf-wrap-anywhere">{other?.name ?? rel.other}</span></li>;
            })}
          </ul>
        </div>
      )}
      {Object.keys(res.properties).length > 0 && (
        <figure className="pf-code" role="region" aria-label="Normalized properties" tabIndex={0}>
          <figcaption className="pf-code-head"><span>Normalized properties</span><span>{res.redacted.length ? `${res.redacted.length} redacted` : ""}</span></figcaption>
          <pre style={{ padding: "8px 12px" }}>{JSON.stringify(res.properties, null, 2)}</pre>
        </figure>
      )}
    </>
  );
}

export function EvidencePanel({ selection, run, onClose }: { selection: Selection; run: RunModel; onClose: () => void }) {
  const ref = useRef<HTMLElement>(null);
  const open = selection !== null;
  useEffect(() => {
    if (!open) return;
    const el = ref.current;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    el?.addEventListener("keydown", onKey);
    if (el && getComputedStyle(el).position === "fixed") el.focus();
    return () => el?.removeEventListener("keydown", onKey);
  }, [open, onClose]);
  return (
    <>
      <div className="pf-scrim" data-open={open} onClick={onClose} aria-hidden />
      <aside className="pf-evidence" data-open={open} aria-label="Evidence" tabIndex={-1} ref={ref}>
        <button type="button" className="pf-btn pf-evidence-close" onClick={onClose}><Icon name="cross" /> Close</button>
        {selection?.kind === "result" ? <ResultBody key={selection.result.id} r={selection.result} run={run} />
          : selection?.kind === "resource" ? <ResourceBody key={selection.resource.id} res={selection.resource} run={run} />
          : <p className="pf-evidence-empty">Select a finding or a resource to see the rule, the cited source lines, any exception and the verified patch.</p>}
      </aside>
    </>
  );
}
