import { useEffect, useRef } from "react";
import { animate, prefersReducedMotion } from "../lib/motion";

export type MarkStatus = "pass" | "fail" | "unknown" | "excepted";

export interface TallyMark {
  id: string;
  status: MarkStatus;
  /** Spoken and tooltip text, e.g. "PF-NET-001 failed on sg-web". */
  label: string;
  href?: string;
}

export interface TallyGroup {
  id: string;
  label: string;
  marks: TallyMark[];
}

const GLYPH: Record<MarkStatus, string> = { pass: "", fail: "", unknown: "?", excepted: "E" };

export function MarkGlyph({ status }: { status: MarkStatus }) {
  if (status === "pass")
    return (
      <svg viewBox="0 0 12 12" aria-hidden fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M2.5 6.4 5 8.8 9.6 3.4" />
      </svg>
    );
  if (status === "fail")
    return (
      <svg viewBox="0 0 12 12" aria-hidden fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round">
        <path d="M3 3l6 6M9 3 3 9" />
      </svg>
    );
  return <span aria-hidden>{GLYPH[status]}</span>;
}

const STATUS_WORD: Record<MarkStatus, string> = { pass: "passed", fail: "failed", unknown: "not evaluated", excepted: "excepted" };

/** One mark per evaluated check, grouped by rule pack, then one empty box per resource no rule evaluated. */
export function Tally({ groups, uncovered, runKey }: { groups: TallyGroup[]; uncovered: string[]; runKey: string }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    if (prefersReducedMotion()) return;
    const marks = ref.current?.querySelectorAll(".pf-mark");
    if (!marks) return;
    const step = Math.min(12, 600 / Math.max(1, marks.length));
    marks.forEach((el, i) =>
      animate(el, [{ opacity: 0, transform: "scale(0.6)" }, { opacity: 1, transform: "none" }], { duration: 180, delay: i * step }),
    );
  }, [runKey]);
  return (
    <div className="pf-tally" ref={ref}>
      {groups.map((g) => {
        const failed = g.marks.filter((m) => m.status === "fail").length;
        const unknown = g.marks.filter((m) => m.status === "unknown").length;
        return (
          <div key={g.id} className="pf-pack">
            <ul className="pf-pack-marks" aria-label={`${g.label}: ${g.marks.length} checks, ${failed} failed, ${unknown} not evaluated`} style={{ listStyle: "none" }}>
              {g.marks.map((m) => (
                <li key={m.id}>
                  {m.href ? (
                    <a className="pf-mark" data-s={m.status} href={m.href} title={m.label} aria-label={`${m.label} (${STATUS_WORD[m.status]})`}>
                      <MarkGlyph status={m.status} />
                    </a>
                  ) : (
                    <span className="pf-mark" data-s={m.status} title={m.label} role="img" aria-label={`${m.label} (${STATUS_WORD[m.status]})`}>
                      <MarkGlyph status={m.status} />
                    </span>
                  )}
                </li>
              ))}
            </ul>
            <span className="pf-pack-label"><strong>{g.label}</strong> {g.marks.length} checks{failed ? `, ${failed} failed` : ""}{unknown ? `, ${unknown} not evaluated` : ""}</span>
          </div>
        );
      })}
      {uncovered.length > 0 && (
        <div className="pf-pack">
          <ul className="pf-pack-marks" aria-label={`${uncovered.length} resources no rule evaluated`} style={{ listStyle: "none" }}>
            {uncovered.map((t) => (
              <li key={t}><span className="pf-mark" data-s="uncovered" title={t} role="img" aria-label={`${t}: not evaluated by any rule`} /></li>
            ))}
          </ul>
          <span className="pf-pack-label"><strong>No rule</strong> {uncovered.length} {uncovered.length === 1 ? "resource" : "resources"}</span>
        </div>
      )}
    </div>
  );
}

export function TallyLegend() {
  const items: [MarkStatus | "uncovered", string][] = [
    ["pass", "Passed"], ["fail", "Failed"], ["unknown", "Could not be evaluated"], ["excepted", "Excepted"], ["uncovered", "Resource no rule evaluated"],
  ];
  return (
    <ul className="pf-legend" aria-label="Legend">
      {items.map(([s, label]) => (
        <li key={s}>
          <span className="pf-mark" data-s={s} aria-hidden>{s !== "uncovered" && <MarkGlyph status={s} />}</span>
          {label}
        </li>
      ))}
    </ul>
  );
}
