import { useMemo, useState } from "react";
import { DiffView, parseUnifiedDiff } from "../components/Code";
import { Disclosure, Segmented } from "../components/Controls";
import { type Selection, Severity, StatusMark } from "../components/Evidence";
import { Icon } from "../components/Icon";
import type { CheckResult, CheckStatus, ExceptionEntry, Pack, Patch, Resource, RunModel } from "../data/model";
import { PACKS, SEVERITY_RANK, typeLabel } from "../data/model";

type Props = { run: RunModel; select: (s: Selection) => void; selection: Selection };

const packLabel = (p: Pack) => PACKS.find((x) => x.id === p)?.label ?? p;

function Head({ title, children }: { title: string; children?: React.ReactNode }) {
  return (
    <div className="pf-section-head">
      <h2 className="pf-h2" tabIndex={-1} data-tab-heading>{title}</h2>
      {children && <p className="pf-prose pf-tone-muted">{children}</p>}
    </div>
  );
}

const Region = ({ label, children }: { label: string; children: React.ReactNode }) => (
  <div className="pf-table-wrap" tabIndex={0} role="region" aria-label={label}>{children}</div>
);

function Chip({ pressed, onClick, children }: { pressed: boolean; onClick: () => void; children: React.ReactNode }) {
  return <button type="button" className="pf-chip" aria-pressed={pressed} onClick={onClick}>{children}</button>;
}

/* Findings ---------------------------------------------------------------------------------- */

export function FindingsTab({ run, select, selection }: Props) {
  const [show, setShow] = useState<"fail" | "excepted" | "unknown">("fail");
  const [pack, setPack] = useState<Pack | null>(null);
  const shown = run.results.filter((r) => r.status === show && (!pack || r.pack === pack));
  const byResource = useMemo(() => {
    const m = new Map<string, CheckResult[]>();
    for (const r of shown) m.set(r.resourceId, [...(m.get(r.resourceId) ?? []), r]);
    return [...m.entries()].sort((a, b) => Math.max(...b[1].map((r) => SEVERITY_RANK[r.severity])) - Math.max(...a[1].map((r) => SEVERITY_RANK[r.severity])) || a[0].localeCompare(b[0]));
  }, [shown]);
  const count = (s: CheckStatus) => run.results.filter((r) => r.status === s && (!pack || r.pack === pack)).length;
  const isSel = (r: CheckResult) => selection?.kind === "result" && selection.result.id === r.id;
  return (
    <>
      <Head title="Findings by resource">
        Each failed check cites the file and line it came from. Checks covered by a valid exception and checks that could not be
        evaluated are listed separately; neither counts as passed.
      </Head>
      <div className="pf-filters">
        <Segmented label="Show" value={show} onChange={setShow} options={[
          { value: "fail", label: `Failed ${count("fail")}` },
          { value: "unknown", label: `Not evaluated ${count("unknown")}` },
          { value: "excepted", label: `Excepted ${count("excepted")}` },
        ]} />
        <div className="pf-filters" role="group" aria-label="Rule pack">
          <Chip pressed={pack === null} onClick={() => setPack(null)}>All packs</Chip>
          {run.params.rulePacks.map((p) => <Chip key={p} pressed={pack === p} onClick={() => setPack(p)}>{packLabel(p)}</Chip>)}
        </div>
      </div>
      {byResource.length === 0 ? (
        <p className="pf-sheet-note">
          {show === "fail" ? "No evaluated check failed for this filter. That says nothing about the checks that could not be evaluated or the resource types with no rule; see the coverage statement above."
            : show === "unknown" ? "Every applicable check in this filter could be evaluated."
            : "No finding in this filter is covered by an exception."}
        </p>
      ) : (
        <ul className="pf-cases" aria-label="Resources with results">
          {byResource.map(([rid, results]) => {
            const res = run.resources.find((x) => x.id === rid);
            return (
              <li key={rid} className="pf-case">
                <div className="pf-case-head">
                  <button type="button" className="pf-case-name pf-mono" style={{ all: "unset", cursor: "pointer", fontWeight: 700 }} onClick={() => res && select({ kind: "resource", resource: res })}>{res?.name ?? rid}</button>
                  <span className="pf-small">{res ? typeLabel(res.type) : ""}</span>
                  {res && <span className="pf-cite">{res.source.file}{res.source.line ? `:${res.source.line}` : ""}</span>}
                </div>
                <ul className="pf-findings">
                  {results.map((r) => (
                    <li key={r.id}>
                      <button type="button" className="pf-finding" aria-pressed={isSel(r)} onClick={() => select({ kind: "result", result: r })}>
                        <StatusMark status={r.status} />
                        <span className="pf-finding-title">
                          <span>{run.rules.find((x) => x.id === r.ruleId)?.title ?? r.ruleId}</span>
                          <span className="pf-small"><span className="pf-mono">{r.ruleId}</span>{r.source?.line ? `, line ${r.source.line}` : ""}</span>
                        </span>
                        <Severity level={r.severity} />
                      </button>
                    </li>
                  ))}
                </ul>
              </li>
            );
          })}
        </ul>
      )}
    </>
  );
}

/* Inventory --------------------------------------------------------------------------------- */

export function InventoryTab({ run, select, selection }: Props) {
  const types = useMemo(() => [...new Set(run.resources.map((r) => r.type))].sort((a, b) => (a === "unsupported" ? 1 : b === "unsupported" ? -1 : a.localeCompare(b))), [run]);
  const [type, setType] = useState<string | null>(null);
  const list = run.resources.filter((r) => !type || r.type === type);
  const marks = (res: Resource) => run.results.filter((r) => r.resourceId === res.id);
  const isSel = (r: Resource) => selection?.kind === "resource" && selection.resource.id === r.id;
  return (
    <>
      <Head title="Inventory">
        {run.resources.length} resources normalized from the {run.params.snapshot} snapshot by the {run.provider === "azure" ? "PowerShell" : "Bash and jq"} adapter.
        Types with no rule are kept and marked, never dropped.
      </Head>
      <div className="pf-filters" role="group" aria-label="Resource type">
        <Chip pressed={type === null} onClick={() => setType(null)}>All <span className="pf-num">{run.resources.length}</span></Chip>
        {types.map((t) => <Chip key={t} pressed={type === t} onClick={() => setType(t)}>{typeLabel(t)} <span className="pf-num">{run.resources.filter((r) => r.type === t).length}</span></Chip>)}
      </div>
      <div className="pf-wide-only">
        <Region label="Resources">
          <table className="pf-table">
            <thead><tr><th scope="col">Resource</th><th scope="col">Type</th><th scope="col">Region</th><th scope="col">Checks</th><th scope="col">Source</th></tr></thead>
            <tbody>
              {list.map((res) => (
                <tr key={res.id} aria-selected={isSel(res)}>
                  <th scope="row" style={{ fontWeight: 500 }}>
                    <button type="button" className="pf-mono" style={{ all: "unset", cursor: "pointer", textDecoration: "underline", textUnderlineOffset: 3 }} onClick={() => select({ kind: "resource", resource: res })}>{res.name}</button>
                  </th>
                  <td>{res.supported ? typeLabel(res.type) : <span className="pf-tag pf-tone-unknown">No rule: {res.nativeType}</span>}</td>
                  <td>{res.region}</td>
                  <td><span style={{ display: "inline-flex", gap: 3, flexWrap: "wrap" }}>{marks(res).map((m) => <StatusMark key={m.id} status={m.status} />)}</span>{marks(res).length === 0 && <span className="pf-small">none</span>}</td>
                  <td className="pf-cite">{res.source.file.split("/").pop()}{res.source.line ? `:${res.source.line}` : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </Region>
      </div>
      <ul className="pf-cards" aria-label="Resources">
        {list.map((res) => (
          <li key={res.id} className="pf-card">
            <p className="pf-case-name pf-mono">{res.name}</p>
            <p className="pf-small">{res.supported ? typeLabel(res.type) : `No rule: ${res.nativeType}`}{res.region ? `, ${res.region}` : ""}</p>
            <span style={{ display: "inline-flex", gap: 3, flexWrap: "wrap" }}>{marks(res).map((m) => <StatusMark key={m.id} status={m.status} />)}</span>
            <div><button type="button" className="pf-btn" onClick={() => select({ kind: "resource", resource: res })}>Open resource</button></div>
          </li>
        ))}
      </ul>
    </>
  );
}

/* Policies ---------------------------------------------------------------------------------- */

export function PoliciesTab({ run }: Props) {
  const tests = run.ruleTests;
  return (
    <>
      <Head title="Policy catalog">
        The bounded rule set this run evaluated, with what each rule checks and, as explicitly, what it does not.
      </Head>
      {run.params.rulePacks.map((p) => {
        const rules = run.rules.filter((r) => r.pack === p);
        return (
          <section key={p} style={{ display: "grid", gap: 10 }} aria-label={`${packLabel(p)} rules`}>
            <h3 className="pf-h3">{packLabel(p)}</h3>
            {rules.length === 0 && <p className="pf-small">No rule in this pack applies to {run.provider.toUpperCase()} snapshots; the pack was requested but evaluated nothing.</p>}
            <ul style={{ listStyle: "none", display: "grid", gap: 10 }}>
              {rules.map((rule) => {
                const res = run.results.filter((r) => r.ruleId === rule.id);
                const t = tests.filter((x) => x.ruleId === rule.id);
                return (
                  <li key={rule.id} className="pf-card">
                    <div className="pf-toolbar" style={{ justifyContent: "space-between" }}>
                      <p className="pf-h3"><span className="pf-mono">{rule.id}</span> {rule.title}</p>
                      <Severity level={rule.severity} />
                    </div>
                    <p>{rule.checks}</p>
                    <p className="pf-small">
                      In this run: {res.filter((r) => r.status === "fail").length} failed, {res.filter((r) => r.status === "pass").length} passed,{" "}
                      {res.filter((r) => r.status === "unknown").length} not evaluated, {res.filter((r) => r.status === "excepted").length} excepted.
                      Fixture tests: {t.filter((x) => x.passed).length} of {t.length} pass.
                    </p>
                    <Disclosure summary={<span className="pf-small">Not evaluated, remediation and scope</span>}>
                      <div style={{ display: "grid", gap: 8 }}>
                        <ul style={{ paddingLeft: 18 }} className="pf-small">{rule.notEvaluated.map((n) => <li key={n}>{n}</li>)}</ul>
                        <p className="pf-small">Remediation: {rule.remediation.kind === "auto" ? "automatic patch, verified before it is offered" : "manual"}. {rule.remediation.detail}</p>
                        <p className="pf-small">Applies to {rule.resourceTypes.map(typeLabel).join(", ")} on {rule.providers.map((x) => x.toUpperCase()).join(" and ")}.</p>
                      </div>
                    </Disclosure>
                  </li>
                );
              })}
            </ul>
          </section>
        );
      })}
    </>
  );
}

/* Rule tests -------------------------------------------------------------------------------- */

export function TestsTab({ run }: Props) {
  const kinds = ["positive", "negative", "boundary"] as const;
  const rules = run.rules;
  const cell = (ruleId: string, kind: string) => {
    const t = run.ruleTests.filter((x) => x.ruleId === ruleId && x.kind === kind);
    const ok = t.filter((x) => x.passed).length;
    return { total: t.length, ok };
  };
  const failing = run.ruleTests.filter((t) => !t.passed);
  return (
    <>
      <Head title="Rule tests">
        Every rule ships with positive (must fail), negative (must pass) and boundary fixtures, run with <span className="pf-mono">opa test</span> inside this run.
        {" "}{run.ruleTests.length} tests, {run.ruleTests.length - failing.length} passing.
      </Head>
      <div className="pf-matrix" role="table" aria-label="Fixture tests per rule">
        <div role="row" style={{ display: "contents" }}>
          <span className="pf-mh" role="columnheader">Rule</span>
          {kinds.map((k) => <span key={k} className="pf-mh" role="columnheader">{k.charAt(0).toUpperCase() + k.slice(1)}</span>)}
        </div>
        {rules.map((r) => (
          <div key={r.id} role="row" style={{ display: "contents" }}>
            <span role="rowheader"><span className="pf-mono">{r.id}</span> <span className="pf-small">{r.title}</span></span>
            {kinds.map((k) => {
              const c = cell(r.id, k);
              const ok = c.total > 0 && c.ok === c.total;
              return (
                <span key={k} role="cell" className={ok ? "pf-tone-pass" : "pf-tone-fail"} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
                  <Icon name={ok ? "check" : "cross"} label={ok ? "All pass" : c.total === 0 ? "Missing" : "Failing"} /> <span className="pf-num">{c.ok}/{c.total}</span>
                </span>
              );
            })}
          </div>
        ))}
      </div>
      {failing.length > 0 && (
        <div className="pf-sheet-note" role="status">
          <p className="pf-h3">Failing tests</p>
          <ul style={{ paddingLeft: 18 }}>{failing.map((t) => <li key={t.name} className="pf-mono">{t.name}</li>)}</ul>
        </div>
      )}
    </>
  );
}

/* Exceptions -------------------------------------------------------------------------------- */

function days(a: string, b: string) {
  return Math.round((Date.parse(`${b}T00:00:00Z`) - Date.parse(`${a}T00:00:00Z`)) / 86_400_000);
}

function Validity({ e, asOf }: { e: ExceptionEntry; asOf: string }) {
  const start = e.created < asOf ? e.created : asOf;
  const endRaw = e.expires && /^\d{4}-\d{2}-\d{2}$/.test(e.expires) ? e.expires : asOf;
  const end = endRaw > asOf ? endRaw : asOf;
  const span = Math.max(1, days(start, end));
  const left = (days(start, e.created) / span) * 100;
  const width = Math.max(1, (days(e.created, endRaw) / span) * 100);
  const at = (days(start, asOf) / span) * 100;
  return (
    <div className="pf-validity" data-state={e.state} role="img" aria-label={`Valid from ${e.created} to ${e.expires || "no expiry"}; evaluated as of ${asOf}`}>
      <span className="pf-span" style={{ left: `${left}%`, width: `${Math.min(100 - left, width)}%` }} />
      <span className="pf-asof" style={{ left: `calc(${at}% - 1px)` }} />
    </div>
  );
}

const STATE_TEXT = { active: "Active", expired: "Expired", rejected: "Rejected", not_yet_active: "Not yet active" } as const;

export function ExceptionsTab({ run }: Props) {
  return (
    <>
      <Head title="Exception registry">
        Exceptions name one rule and one exact resource, carry an owner, a reason and a ticket, and expire within 90 days. Evaluated as of {run.params.asOf}.
        An excepted finding stays listed; an expired or malformed exception is reported, not applied. Each bar spans an exception's
        validity window; the upright tick marks {run.params.asOf}.
      </Head>
      {run.exceptions.length === 0 ? <p className="pf-sheet-note">The registry is empty for this snapshot.</p> : (
        <ul style={{ listStyle: "none", display: "grid", gap: 10 }} aria-label="Exceptions">
          {run.exceptions.map((e) => (
            <li key={e.id} className="pf-card">
              <div className="pf-toolbar" style={{ justifyContent: "space-between" }}>
                <p className="pf-h3"><span className="pf-mono">{e.id}</span> <span className="pf-small">for</span> <span className="pf-mono">{e.ruleId}</span></p>
                <span className={`pf-tag ${e.state === "active" ? "pf-tone-pass" : e.state === "rejected" ? "pf-tone-fail" : "pf-tone-muted"}`}>
                  <Icon name={e.state === "active" ? "check" : e.state === "rejected" ? "cross" : "info"} /> {STATE_TEXT[e.state]}
                </span>
              </div>
              <p className="pf-mono pf-wrap-anywhere pf-small">{e.resourceId}</p>
              <p>{e.reason}</p>
              <Validity e={e} asOf={run.params.asOf} />
              <p className="pf-small">Created {e.created}, expires {e.expires || "never (not allowed)"}; owner {e.owner || "missing"}; {e.ticket || "no ticket"}.</p>
              <p className="pf-small">Effect in this review: {e.effect}.</p>
              {e.problems.length > 0 && <ul style={{ paddingLeft: 18 }} className="pf-small pf-tone-fail">{e.problems.map((p) => <li key={p}>{p}</li>)}</ul>}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

/* Remediation -------------------------------------------------------------------------------- */

const sentence = (t: string) => (t ? t.charAt(0).toUpperCase() + t.slice(1) : t);

function PatchCard({ p, name, open = false }: { p: Patch; name: string; open?: boolean }) {
  const [mode, setMode] = useState<"diff" | "before" | "after">("diff");
  const diffs = p.state === "accepted" ? parseUnifiedDiff(p.diff) : [];
  return (
    <li className="pf-card">
      <div className="pf-toolbar" style={{ justifyContent: "space-between" }}>
        <p className="pf-h3"><span className="pf-mono">{p.ruleId}</span> on <span className="pf-mono pf-wrap-anywhere">{name}</span></p>
        <span className={`pf-tag ${p.state === "accepted" ? "pf-tone-pass" : "pf-tone-fail"}`}><Icon name={p.state === "accepted" ? "check" : "cross"} /> {p.state === "accepted" ? "Verified" : p.state === "withheld" ? "Withheld" : "Rejected"}</span>
      </div>
      <p className="pf-small">{sentence(p.strategy)}</p>
      {diffs.length > 0 && (
        <Disclosure defaultOpen={open} summary={<span className="pf-small">Patch for <span className="pf-mono">{diffs.map((d) => d.file.split("/").pop()).join(", ")}</span></span>}>
          <div style={{ display: "grid", gap: 10 }}>
            <Segmented label={`Patch view for ${p.id}`} value={mode} onChange={setMode} options={[{ value: "diff", label: "Changes" }, { value: "before", label: "Before" }, { value: "after", label: "After" }]} />
            {diffs.map((d) => <DiffView key={d.file} diff={d} mode={mode} />)}
          </div>
        </Disclosure>
      )}
      {p.state !== "accepted" && <p className="pf-tone-fail">{p.reason}</p>}
      <ul style={{ listStyle: "none", display: "grid", gap: 4 }} aria-label="Regression evidence">
        {p.regression.map((c) => (
          <li key={c.label} style={{ display: "grid", gridTemplateColumns: "auto minmax(0, 1fr)", gap: 8 }}>
            <span className={c.passed ? "pf-tone-pass" : "pf-tone-fail"}><Icon name={c.passed ? "check" : "cross"} label={c.passed ? "Held" : "Did not hold"} /></span>
            <span>{c.label} <span className="pf-small">{c.detail}</span></span>
          </li>
        ))}
      </ul>
    </li>
  );
}

export function RemediationTab({ run }: Props) {
  if (!run.remediationRequested)
    return (
      <>
        <Head title="Remediation" />
        <p className="pf-sheet-note">This run was requested with remediation off, so no patches were generated. Request a run with remediation set to propose to see verified patches.</p>
      </>
    );
  const accepted = run.patches.filter((p) => p.state === "accepted");
  const nameOf = (id: string) => run.resources.find((r) => r.id === id)?.name ?? id.split(":").pop() ?? id;
  const other = run.patches.filter((p) => p.state !== "accepted");
  return (
    <>
      <Head title="Remediation">
        Each patch was applied to a copy of the snapshot and the whole review re-run. It is offered only if its finding is resolved, every other
        result is unchanged and no other resource changed. Patches change local files only; nothing is applied to any cloud account.
      </Head>
      <div className="pf-toolbar">
        {run.patchUrl && accepted.length > 0 ? (
          <a className="pf-btn pf-btn-primary" href={run.patchUrl} download>Download remediation.patch ({accepted.length} verified)</a>
        ) : <span className="pf-small">No verified patch to download.</span>}
        <span className="pf-small">Apply from a checkout with <span className="pf-mono">git apply remediation.patch</span>.</span>
      </div>
      <ul style={{ listStyle: "none", display: "grid", gap: 12 }} aria-label="Verified patches">{accepted.map((p, i) => <PatchCard key={p.id} p={p} name={nameOf(p.resourceId)} open={i === 0} />)}</ul>
      {other.length > 0 && (
        <section style={{ display: "grid", gap: 10 }} aria-label="Patches not offered">
          <h3 className="pf-h3">Not offered</h3>
          <ul style={{ listStyle: "none", display: "grid", gap: 12 }}>{other.map((p) => <PatchCard key={p.id} p={p} name={nameOf(p.resourceId)} />)}</ul>
        </section>
      )}
    </>
  );
}
