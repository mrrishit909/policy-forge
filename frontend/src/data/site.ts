import { useCallback, useEffect, useRef, useState } from "react";
import { adapt, type RawRun } from "./adapter";
import { fetchJson } from "./load";
import type { RunModel } from "./model";

export interface Snapshot {
  project: string;
  mode: "state-snapshot" | "fixture";
  generated_at: string;
  source_commit: string;
  state_commit: string;
  latest_run_id: string | null;
  runs_included: string[];
  stale_after_hours: number;
  files?: { release: boolean; memory: boolean };
}

export interface IndexEntry {
  run_id: string;
  request_id: string;
  status: string;
  attempt: number;
  created_at: string;
  completed_at: string | null;
  source: string;
  issue: number | null;
  headline: string | null;
}

export interface Release {
  release_id: string;
  status: "released" | "blocked";
  created_at: string;
}

export interface SiteData {
  snapshot: Snapshot;
  index: IndexEntry[];
  release: Release | null;
}

export type LoadState<T> =
  | { status: "loading" }
  | { status: "error"; error: Error }
  | { status: "empty" }
  | { status: "ready"; data: T; stale: boolean };

export function isStale(s: Snapshot, now = Date.now()): boolean {
  const t = Date.parse(s.generated_at);
  return Number.isFinite(t) && now - t > s.stale_after_hours * 3600_000;
}

export function useSiteData(dataUrl: string): { state: LoadState<SiteData>; reload: () => void } {
  const [state, setState] = useState<LoadState<SiteData>>({ status: "loading" });
  const [tick, setTick] = useState(0);
  useEffect(() => {
    const ctrl = new AbortController();
    setState({ status: "loading" });
    (async () => {
      try {
        const snapshot = await fetchJson<Snapshot>(`${dataUrl}snapshot.json`, ctrl.signal);
        const index = await fetchJson<{ runs: IndexEntry[] }>(`${dataUrl}index.json`, ctrl.signal);
        const release = snapshot.files?.release ? await fetchJson<Release>(`${dataUrl}release.json`, ctrl.signal) : null;
        if (!snapshot.latest_run_id) {
          setState({ status: "empty" });
          return;
        }
        setState({ status: "ready", data: { snapshot, index: index.runs, release }, stale: isStale(snapshot) });
      } catch (err) {
        if (!ctrl.signal.aborted) setState({ status: "error", error: err as Error });
      }
    })();
    return () => ctrl.abort();
  }, [dataUrl, tick]);
  return { state, reload: useCallback(() => setTick((t) => t + 1), []) };
}

const FILES = ["run.json", "manifest.json", "summary.json", "coverage.json", "findings.json", "inventory.json", "relationships.json",
  "exceptions.json", "rule_tests.json", "remediation.json", "catalog.json"] as const;

async function loadRun(dataUrl: string, runId: string, signal: AbortSignal): Promise<RunModel> {
  const base = `${dataUrl}runs/${encodeURIComponent(runId)}/`;
  const json = await Promise.all(FILES.map((f) => fetchJson<unknown>(base + f, signal)));
  const raw = Object.fromEntries(FILES.map((f, i) => [f.replace(".json", ""), json[i]])) as unknown as RawRun;
  return adapt(raw, base);
}

export function useRun(dataUrl: string, runId: string | null, tick: number): LoadState<RunModel> {
  const cache = useRef(new Map<string, RunModel>());
  const [state, setState] = useState<LoadState<RunModel>>({ status: "loading" });
  useEffect(() => { cache.current.clear(); }, [tick]);
  useEffect(() => {
    if (!runId) {
      setState({ status: "empty" });
      return;
    }
    const hit = cache.current.get(runId);
    if (hit) {
      setState({ status: "ready", data: hit, stale: false });
      return;
    }
    const ctrl = new AbortController();
    setState({ status: "loading" });
    loadRun(dataUrl, runId, ctrl.signal).then(
      (data) => { cache.current.set(runId, data); setState({ status: "ready", data, stale: false }); },
      (error) => { if (!ctrl.signal.aborted) setState({ status: "error", error }); },
    );
    return () => ctrl.abort();
  }, [dataUrl, runId, tick]);
  return state;
}
