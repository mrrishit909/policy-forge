import { type MouseEvent, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { TabBoundary } from "./components/Boundary";
import { EmptyState, ErrorState, Segmented } from "./components/Controls";
import { EvidencePanel, type Selection } from "./components/Evidence";
import { Icon } from "./components/Icon";
import { Tally, type TallyGroup, TallyLegend } from "./components/Tally";
import { type AppConfig, resolveConfig, type Theme } from "./config";
import { PACKS, type RunModel } from "./data/model";
import { type SiteData, useRun, useSiteData } from "./data/site";
import { ago } from "./lib/format";
import { animate } from "./lib/motion";
import { parseRoute, type Route, routeHref, TABS, type TabId, useRoute } from "./routing";
import { AboutView, HistoryView, RequestView } from "./views/Pages";
import { ExceptionsTab, FindingsTab, InventoryTab, PoliciesTab, RemediationTab, TestsTab } from "./views/Tabs";
import "./styles/app.css";

const TAB_VIEWS: Record<TabId, typeof FindingsTab> = {
  findings: FindingsTab, inventory: InventoryTab, policies: PoliciesTab, tests: TestsTab, exceptions: ExceptionsTab, remediation: RemediationTab,
};

function useResolvedTheme(theme: Theme): "light" | "dark" {
  const q = "(prefers-color-scheme: dark)";
  const [system, setSystem] = useState<"light" | "dark">(() => (typeof window !== "undefined" && window.matchMedia?.(q).matches ? "dark" : "light"));
  useEffect(() => {
    const mq = window.matchMedia?.(q);
    if (!mq) return;
    const on = () => setSystem(mq.matches ? "dark" : "light");
    mq.addEventListener("change", on);
    return () => mq.removeEventListener("change", on);
  }, []);
  return theme === "auto" ? system : theme;
}

function Skeleton() {
  return (
    <div className="pf-skeleton" role="status" aria-live="polite">
      <p className="pf-small">Loading the published review.</p>
      <div className="pf-skel" style={{ height: 34, width: "58%" }} />
      <div className="pf-skel" style={{ height: 70 }} />
      <div className="pf-skel" style={{ height: 44, width: "80%" }} />
      <div className="pf-skel" style={{ height: 260, borderRadius: 8 }} />
    </div>
  );
}

function tabCount(run: RunModel, tab: TabId): number {
  switch (tab) {
    case "findings": return run.results.filter((r) => r.status === "fail").length;
    case "inventory": return run.resources.length;
    case "policies": return run.rules.length;
    case "tests": return run.ruleTests.length;
    case "exceptions": return run.exceptions.length;
    case "remediation": return run.patches.filter((p) => p.state === "accepted").length;
  }
}

function Coverage({ run }: { run: RunModel }) {
  const [full, setFull] = useState(false);
  const groups: TallyGroup[] = run.params.rulePacks.map((p) => ({
    id: p,
    label: PACKS.find((x) => x.id === p)?.label ?? p,
    marks: run.results.filter((r) => r.pack === p).map((r) => ({
      id: r.id,
      status: r.status,
      label: `${r.ruleId} on ${run.resources.find((x) => x.id === r.resourceId)?.name ?? r.resourceId}`,
    })),
  }));
  const s = run.summary;
  return (
    <section className="pf-sheet pf-coverage" aria-labelledby="pf-statement">
      <p className="pf-runline pf-wrap-anywhere">
        Snapshot <span className="pf-mono">{run.params.snapshot}</span>, exceptions as of {run.params.asOf}, remediation {run.params.remediation === "propose" ? "proposed" : "off"}.
        Run <span className="pf-mono">{run.record.runId}</span>.
      </p>
      <h1 className="pf-statement" id="pf-statement">{headline(run)}</h1>
      <div className="pf-statement-full" data-open={full}>
        <p className="pf-prose pf-tone-muted" id="pf-coverage-statement">{s.coverageStatement}</p>
        <button type="button" className="pf-linkbtn" aria-expanded={full} aria-controls="pf-coverage-statement" onClick={() => setFull((v) => !v)}>
          {full ? "Show less" : "Read the full coverage statement"}
        </button>
      </div>
      <p className="pf-counts">
        <span><b>{s.failed}</b> active {s.failed === 1 ? "finding" : "findings"}</span>
        <span><b>{s.unknown}</b> could not be evaluated</span>
        <span><b>{s.excepted}</b> excepted</span>
        <span><b>{s.passed}</b> passed</span>
        <span><b>{s.uncovered.length}</b> {s.uncovered.length === 1 ? "resource" : "resources"} no rule evaluated</span>
        {!s.completeCoverage && <span className="pf-tone-unknown"><Icon name="warn" /> Partial coverage</span>}
      </p>
      <Tally groups={groups} uncovered={s.uncovered} runKey={run.record.runId} />
      <TallyLegend />
    </section>
  );
}

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** A count-only sentence; the verdict-free coverage statement from summary.json follows it verbatim. */
export function headline(run: RunModel): string {
  const s = run.summary;
  const failed = s.failed + s.excepted;
  const excepted = s.excepted ? ` (${s.excepted} covered by an exception)` : "";
  return `${plural(failed, "check failed", "checks failed")}${excepted}, ${s.unknown} could not be evaluated, and ${plural(s.uncovered.length, "resource was", "resources were")} not evaluated by any rule.`;
}

function runLabel(site: SiteData, id: string): string {
  const entry = site.index.find((r) => r.run_id === id);
  const when = entry?.created_at.slice(0, 16).replace("T", " ") ?? "";
  return entry?.headline ? `${when} UTC, ${entry.headline.split(":")[0]}` : `${when} ${id}`;
}

export function PolicyForgeApp(props: Partial<AppConfig>) {
  const config = useMemo(() => resolveConfig(props), [props.basePath, props.dataUrl, props.theme, props.showShell, props.routing, props.repoUrl, props.siteUrl]); // eslint-disable-line react-hooks/exhaustive-deps
  const [themeChoice, setThemeChoice] = useState<Theme>(config.theme);
  const theme = useResolvedTheme(themeChoice);
  const [route, navigate] = useRoute(config.routing);
  const { state, reload } = useSiteData(config.dataUrl);
  const [tick, setTick] = useState(0);
  const [selection, setSelection] = useState<Selection>(null);
  const sheet = useRef<HTMLDivElement>(null);
  const prevTab = useRef<TabId | null>(null);

  const latest = state.status === "ready" ? state.data.snapshot.latest_run_id : null;
  const runId = route.view === "run" ? route.runId ?? latest : null;
  const run = useRun(config.dataUrl, state.status === "ready" ? runId : null, tick);
  const tab: TabId = route.view === "run" ? route.tab : "findings";

  const refresh = () => { reload(); setTick((t) => t + 1); };
  const close = useCallback(() => setSelection(null), []);

  // Tab change: the sheet content slides in the tab's direction, then focus moves to its heading.
  useEffect(() => {
    if (route.view !== "run") { prevTab.current = null; return; }
    const before = prevTab.current;
    prevTab.current = tab;
    setSelection(null);
    if (before === null || before === tab) return;
    const dir = TABS.findIndex((t) => t.id === tab) > TABS.findIndex((t) => t.id === before) ? 1 : -1;
    animate(sheet.current, [{ opacity: 0, transform: `translateX(${dir * 16}px)` }, { opacity: 1, transform: "none" }], { duration: 220 });
    sheet.current?.querySelector<HTMLElement>("[data-tab-heading]")?.focus({ preventScroll: true });
  }, [tab, route.view]);

  const onClick = (e: MouseEvent<HTMLDivElement>) => {
    const a = (e.target as HTMLElement).closest("a");
    const href = a?.getAttribute("href");
    if (!a || !href?.startsWith("#/") || e.metaKey || e.ctrlKey || e.shiftKey || e.button !== 0) return;
    if (config.routing === "memory") { e.preventDefault(); navigate(parseRoute(href)); }
  };

  const tabHref = (t: TabId) => routeHref({ view: "run", runId: route.view === "run" ? route.runId : undefined, tab: t });

  let body: React.ReactNode;
  if (state.status === "loading" || (route.view === "run" && state.status === "ready" && run.status === "loading")) body = <Skeleton />;
  else if (state.status === "error") body = <div className="pf-state"><ErrorState title="The review snapshot did not load" error={state.error} onRetry={refresh} /></div>;
  else if (route.view === "request") body = <RequestView config={config} />;
  else if (route.view === "about") body = <AboutView config={config} />;
  else if (state.status === "empty") body = <EmptyState requestHref="#/request" />;
  else if (state.status !== "ready") body = <Skeleton />;
  else if (route.view === "history") body = <HistoryView site={state.data} config={config} />;
  else if (run.status === "error") body = <div className="pf-state"><ErrorState title={runId && !state.data.snapshot.runs_included.includes(runId) ? `Review ${runId} is not in this snapshot` : "This review did not load"} error={run.error} onRetry={refresh} /></div>;
  else if (run.status === "ready") {
    const model = run.data;
    const View = TAB_VIEWS[tab];
    body = (
      <div className="pf-page">
        <Coverage run={model} />
        <div className="pf-folder">
          <nav aria-label="Review sections">
            <ul className="pf-tabs">
              {TABS.map((t) => (
                <li key={t.id} style={{ display: "contents" }}>
                  <a className="pf-tab" href={tabHref(t.id)} aria-current={t.id === tab ? "page" : undefined}>
                    <span className="pf-wide-label">{t.label}</span>
                    <span className="pf-count">{tabCount(model, t.id)}</span>
                  </a>
                </li>
              ))}
            </ul>
          </nav>
          <div className="pf-sheet">
            <div className={tab === "findings" || tab === "inventory" ? "pf-split" : ""}>
              <div className="pf-sheet-body" ref={sheet}>
                <TabBoundary key={tab} label={TABS.find((t) => t.id === tab)!.label}>
                  <View run={model} select={setSelection} selection={selection} />
                </TabBoundary>
              </div>
              {(tab === "findings" || tab === "inventory") && <EvidencePanel selection={selection} run={model} onClose={close} />}
            </div>
          </div>
        </div>
      </div>
    );
  } else body = <Skeleton />;

  const snap = state.status === "ready" ? state.data.snapshot : null;
  const release = state.status === "ready" ? state.data.release : null;
  const topLink = (r: Route, label: string, extra = "") => (
    <a className={extra} href={routeHref(r)} aria-current={route.view === r.view ? "page" : undefined}>{label}</a>
  );
  const runs = state.status === "ready" ? state.data.snapshot.runs_included : [];

  return (
    <div className="pf-root" data-theme={theme} data-shell={config.showShell} onClick={onClick}>
      <a className="pf-skip" href="#pf-main" onClick={(e) => { e.preventDefault(); document.getElementById("pf-main")?.focus(); }}>Skip to content</a>
      {config.showShell && (
        <header className="pf-header">
          <a className="pf-wordmark" href="#/">Policy Forge</a>
          {route.view === "run" && state.status === "ready" && runs.length > 0 && runId && (
            <div className="pf-runpick">
              <label htmlFor="pf-run">Review</label>
              <select id="pf-run" value={runId} onChange={(e) => navigate({ view: "run", runId: e.target.value, tab })}>
                {runs.map((id) => <option key={id} value={id}>{runLabel(state.data, id)}</option>)}
              </select>
            </div>
          )}
          <nav className="pf-nav" aria-label="Primary">
            {topLink({ view: "history" }, "Runs")}
            <a href={routeHref({ view: "request" })} aria-current={route.view === "request" ? "page" : undefined}>Request<span className="pf-hide-sm"> a review</span></a>
            {topLink({ view: "about" }, "About", "pf-hide-sm")}
            <button type="button" onClick={refresh} aria-label="Refresh data from the published snapshot"><Icon name="refresh" /></button>
          </nav>
        </header>
      )}
      {snap?.mode === "fixture" && (
        <div className="pf-banner" role="note"><Icon name="info" /> Fixture data: a real engine run built for automated browser tests, not a published review.</div>
      )}
      {state.status === "ready" && state.stale && snap && (
        <div className="pf-banner" role="status">
          <span className="pf-tone-unknown"><Icon name="warn" /></span>
          <span>This snapshot is {ago(snap.generated_at)} old, older than its 14-day freshness window. The results shown are the last ones published.</span>
          <button type="button" className="pf-btn" onClick={refresh}><Icon name="refresh" /> Refresh</button>
        </div>
      )}
      {release?.status === "blocked" && (
        <div className="pf-banner" role="status"><span className="pf-tone-fail"><Icon name="cross" /></span> The latest release check is blocked.</div>
      )}
      <main id="pf-main" tabIndex={-1} style={{ outline: "none" }}>{body}</main>
      {config.showShell && (
        <footer className="pf-footer">
          <div style={{ display: "grid", gap: 10 }}>
            <p>Synthetic configuration of a fictional organisation, reviewed offline.{snap ? ` Snapshot generated ${snap.generated_at.replace("T", " ").replace("Z", " UTC")}.` : ""}{release ? ` Latest release check: ${release.status}.` : ""}</p>
            <Segmented label="Colour theme" value={themeChoice} options={[{ value: "auto", label: "System" }, { value: "light", label: "Light" }, { value: "dark", label: "Dark" }]} onChange={setThemeChoice} />
          </div>
          <nav aria-label="Project links">
            <a href={config.repoUrl}>Source</a>
            <a href={`${config.repoUrl}/tree/state`}>State branch</a>
            <a href={`${config.repoUrl}/blob/main/docs/ARCHITECTURE.md`}>Architecture</a>
          </nav>
        </footer>
      )}
    </div>
  );
}
