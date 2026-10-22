import { useCallback, useEffect, useState } from "react";
import type { Routing } from "./config";

export const TABS = [
  { id: "findings", label: "Findings", short: "Findings" },
  { id: "inventory", label: "Inventory", short: "Inventory" },
  { id: "policies", label: "Policies", short: "Policies" },
  { id: "tests", label: "Rule tests", short: "Tests" },
  { id: "exceptions", label: "Exceptions", short: "Exceptions" },
  { id: "remediation", label: "Remediation", short: "Patches" },
] as const;

export type TabId = (typeof TABS)[number]["id"];

export type Route =
  | { view: "run"; runId?: string; tab: TabId }
  | { view: "history" }
  | { view: "request" }
  | { view: "about" };

const TAB_IDS = new Set<string>(TABS.map((t) => t.id));

export function parseRoute(hash: string): Route {
  const [head, a, b, c] = hash.replace(/^#\/?/, "").split("/").filter(Boolean).map(decodeURIComponent);
  if (head === "runs" && a && b === "tab" && c && TAB_IDS.has(c)) return { view: "run", runId: a, tab: c as TabId };
  if (head === "runs" && a) return { view: "run", runId: a, tab: "findings" };
  if (head === "runs") return { view: "history" };
  if (head === "tab" && a && TAB_IDS.has(a)) return { view: "run", tab: a as TabId };
  if (head === "request") return { view: "request" };
  if (head === "about") return { view: "about" };
  return { view: "run", tab: "findings" };
}

export function routeHref(route: Route): string {
  const enc = encodeURIComponent;
  switch (route.view) {
    case "run":
      if (route.runId) return `#/runs/${enc(route.runId)}/tab/${route.tab}`;
      return route.tab === "findings" ? "#/" : `#/tab/${route.tab}`;
    case "history":
      return "#/runs";
    case "request":
      return "#/request";
    case "about":
      return "#/about";
  }
}

export function useRoute(mode: Routing): [Route, (r: Route) => void] {
  const [route, setRoute] = useState<Route>(() => (mode === "hash" ? parseRoute(window.location.hash) : { view: "run", tab: "findings" }));
  useEffect(() => {
    if (mode !== "hash") return;
    const onHash = () => setRoute(parseRoute(window.location.hash));
    window.addEventListener("hashchange", onHash);
    return () => window.removeEventListener("hashchange", onHash);
  }, [mode]);
  const navigate = useCallback(
    (r: Route) => {
      if (mode === "hash") window.location.hash = routeHref(r).slice(1);
      else setRoute(r);
    },
    [mode],
  );
  return [route, navigate];
}
