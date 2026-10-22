import { useEffect, useRef } from "react";
import { animate } from "../lib/motion";

/** A redacted window of a source file with its real line numbers; cited lines are marked and scrolled into view. */
export function CodeExcerpt({ file, lines, firstLine, cited, label }: { file: string; lines: string[]; firstLine: number; cited: number[]; label: string }) {
  const set = new Set(cited);
  const ref = useRef<HTMLOListElement>(null);
  useEffect(() => {
    const el = ref.current?.querySelector<HTMLElement>('[data-cited="true"]');
    if (!el) return;
    el.scrollIntoView?.({ block: "nearest" });
    animate(el, [{ backgroundColor: "transparent" }, {}], { duration: 180, delay: 120 });
  }, [file, cited.join(",")]);
  return (
    <figure className="pf-code" role="region" aria-label={label} tabIndex={0}>
      <figcaption className="pf-code-head">
        <span className="pf-wrap-anywhere">{file}</span>
        <span>{cited.length ? `line ${cited.join(", ")}` : ""}</span>
      </figcaption>
      <ol ref={ref} start={firstLine}>
        {lines.map((l, i) => {
          const n = firstLine + i;
          return (
            <li key={n} className="pf-line" data-n={n} data-cited={set.has(n)}>
              <span>{l || " "}</span>
            </li>
          );
        })}
      </ol>
    </figure>
  );
}

export interface DiffLine {
  kind: "add" | "del" | "ctx" | "hunk";
  text: string;
}

export interface FileDiff {
  file: string;
  lines: DiffLine[];
}

/** Parse a unified diff (as written by `git diff` / accepted by `git apply`) into files and lines. */
export function parseUnifiedDiff(patch: string): FileDiff[] {
  const files: FileDiff[] = [];
  let cur: FileDiff | null = null;
  for (const raw of patch.split("\n")) {
    if (raw.startsWith("diff --git ")) continue;
    if (raw.startsWith("--- ")) continue;
    if (raw.startsWith("+++ ")) {
      cur = { file: raw.slice(4).replace(/^b\//, ""), lines: [] };
      files.push(cur);
      continue;
    }
    if (!cur) continue;
    if (raw.startsWith("@@")) cur.lines.push({ kind: "hunk", text: raw });
    else if (raw.startsWith("+")) cur.lines.push({ kind: "add", text: raw.slice(1) });
    else if (raw.startsWith("-")) cur.lines.push({ kind: "del", text: raw.slice(1) });
    else if (raw.startsWith(" ")) cur.lines.push({ kind: "ctx", text: raw.slice(1) });
  }
  return files;
}

const SIGN = { add: "+", del: "-", ctx: " ", hunk: "" } as const;

/** Unified view with +/- markers; "before" and "after" modes hide the other side's lines. */
export function DiffView({ diff, mode }: { diff: FileDiff; mode: "diff" | "before" | "after" }) {
  const lines = diff.lines.filter((l) => (mode === "before" ? l.kind !== "add" : mode === "after" ? l.kind !== "del" : true));
  return (
    <figure className="pf-diff" role="region" aria-label={`Patch for ${diff.file}, ${mode === "diff" ? "changes" : mode}`} tabIndex={0}>
      <figcaption className="pf-diff-file pf-wrap-anywhere">{diff.file}</figcaption>
      <ol>
        {lines.map((l, i) => (
          <li key={i} className="pf-dl" data-k={mode === "diff" || l.kind === "hunk" ? l.kind : "ctx"}>
            <span aria-hidden>{mode === "diff" ? SIGN[l.kind] : ""}</span>
            <span>
              {mode === "diff" && l.kind === "add" && <span className="pf-sr-only">added: </span>}
              {mode === "diff" && l.kind === "del" && <span className="pf-sr-only">removed: </span>}
              {l.text || " "}
            </span>
          </li>
        ))}
      </ol>
    </figure>
  );
}
