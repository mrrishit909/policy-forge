import { Icon } from "../components/Icon";
import type { AppConfig } from "../config";
import type { SiteData } from "../data/site";
import { routeHref } from "../routing";

export function HistoryView({ site, config }: { site: SiteData; config: AppConfig }) {
  const included = new Set(site.snapshot.runs_included);
  return (
    <div className="pf-page" style={{ maxWidth: 1000 }}>
      <div className="pf-section-head">
        <h1 className="pf-h1">Every review, including the ones that failed to run.</h1>
        <p className="pf-prose">
          The ledger lists every recorded attempt. The {included.size} most recent completed reviews are in this site's snapshot;
          older results stay on the state branch.
        </p>
      </div>
      <ol style={{ listStyle: "none", display: "grid", gap: 10 }} aria-label="Review ledger, newest first">
        {site.index.map((r) => (
          <li key={r.run_id} className="pf-card">
            <div className="pf-toolbar" style={{ justifyContent: "space-between" }}>
              {included.has(r.run_id) ? (
                <a className="pf-mono pf-wrap-anywhere" href={routeHref({ view: "run", runId: r.run_id, tab: "findings" })}>{r.run_id}</a>
              ) : (
                <span className="pf-mono pf-wrap-anywhere">{r.run_id}</span>
              )}
              <span className={`pf-tag ${r.status === "completed" ? "pf-tone-pass" : r.status === "failed" ? "pf-tone-fail" : r.status === "blocked" ? "pf-tone-unknown" : "pf-tone-muted"}`}>{r.status}</span>
            </div>
            <p className="pf-small">
              Attempt {r.attempt}, created {r.created_at.replace("T", " ").replace("Z", " UTC")}, source {r.source}
              {r.issue ? <> from <a href={`${config.repoUrl}/issues/${r.issue}`}>issue #{r.issue}</a></> : null}
            </p>
            {r.headline && <p>{r.headline}</p>}
          </li>
        ))}
      </ol>
    </div>
  );
}

export function RequestView({ config }: { config: AppConfig }) {
  return (
    <div className="pf-page" style={{ maxWidth: 780 }}>
      <div className="pf-section-head">
        <h1 className="pf-h1">Request a policy review.</h1>
        <p className="pf-prose">
          This site is read-only. A new review is a GitHub issue that picks a committed synthetic snapshot, the rule packs, whether to
          propose patches, and the date exceptions are evaluated against. A GitHub Actions workflow runs it and publishes the result
          here. Opening an issue needs a GitHub account.
        </p>
      </div>
      <p className="pf-prose">
        The repository owner's requests start automatically. Anyone else's request waits, labelled blocked, until the owner approves it.
        No request can reach a cloud account or start paid AI inference: the review runs Bash, PowerShell, OPA and Python over
        committed files. Uploading your own configuration is not supported.
      </p>
      <ol className="pf-steps" style={{ paddingLeft: 20, display: "grid", gap: 8 }}>
        <li>The intake workflow validates the form against the request schema and labels the issue requested, or blocked with the reason.</li>
        <li>Identical parameters on the current engine link to the existing review instead of running again.</li>
        <li>The review runs on a GitHub-hosted runner, validates its outputs and writes them to the state branch.</li>
        <li>The site redeploys and the issue gets a link to the result, with the evidence kept either way.</li>
      </ol>
      <div className="pf-toolbar">
        <a className="pf-btn pf-btn-primary" href={`${config.repoUrl}/issues/new?template=run-request.yml`}><Icon name="github" /> Open the review request form on GitHub</a>
        <a className="pf-btn" href={`${config.repoUrl}/issues?q=label%3Atype%3Arun`}>See existing requests</a>
      </div>
      <p className="pf-small">Limits keep the desk inside GitHub's free tier: at most 40 runs a month, 5 at a time, 2 MB of results per run.</p>
    </div>
  );
}

export function AboutView({ config }: { config: AppConfig }) {
  const rows: [string, string, string][] = [
    ["Findings, inventory, policies, tests, exceptions, patches", "Cached", "A static snapshot of the state branch, rebuilt after each review; its time is shown in the footer."],
    ["New reviews", "Live, owner-authorized", "Through GitHub Issues and Actions, over committed synthetic snapshots only."],
    ["Applying patches to real infrastructure", "Not supported", "By design: patches change local files and are verified offline."],
    ["Reviewing your own configuration", "Not supported", "The repository and site are public; nothing private is ever uploaded."],
    ["AI grading of the site", "Unavailable", "Optional; runs only if the owner configures inference credentials."],
  ];
  return (
    <div className="pf-page" style={{ maxWidth: 880 }}>
      <div className="pf-section-head">
        <h1 className="pf-h1">How the desk works, and what it does not do.</h1>
        <p className="pf-prose">
          A Bash and jq adapter reads AWS-shaped exports and a PowerShell 7 adapter reads Azure-shaped exports; both write the same
          normalized inventory. Python resolves exact source lines, redacts sensitive fields and links related resources. OPA evaluates a
          bounded set of Rego rules; Conftest checks the inputs and the exception registry. Each proposed patch is applied to a copy of the
          snapshot and the whole review is re-run before it is offered.
        </p>
      </div>
      <ul style={{ listStyle: "disc", paddingLeft: 20, display: "grid", gap: 6 }} className="pf-prose">
        <li>Snapshots are synthetic exports of a fictional organisation, with documentation IP ranges and fake account ids.</li>
        <li>Rules cover public storage access, overly broad IAM permissions, unrestricted ingress, missing supported audit settings and a few risky relationships. Everything else is outside the review and is shown as such.</li>
        <li>IAM conditions, NotAction, NotPrincipal and other semantics the rules do not model make a check "could not be evaluated", never "passed".</li>
        <li>The site never calls a review compliant: it reports what failed, what was excepted and what was not evaluated.</li>
      </ul>
      <div className="pf-table-wrap" tabIndex={0} role="region" aria-label="Capability status">
        <table className="pf-table">
          <thead><tr><th scope="col">Capability</th><th scope="col">Status</th><th scope="col">Detail</th></tr></thead>
          <tbody>
            {rows.map(([a, b, c]) => <tr key={a}><th scope="row" style={{ fontWeight: 500 }}>{a}</th><td>{b}</td><td>{c}</td></tr>)}
          </tbody>
        </table>
      </div>
      <p className="pf-small">Source, workflows and documentation: <a href={config.repoUrl}>{config.repoUrl.replace("https://", "")}</a></p>
    </div>
  );
}
