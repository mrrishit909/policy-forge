/** The site's own view of one run. `adapter.ts` maps the engine's output files onto it. */

export type Pack = "storage" | "iam" | "network" | "audit" | "relationships";
export type CheckStatus = "pass" | "fail" | "unknown" | "excepted";
export type Severity = "critical" | "high" | "medium" | "low";

export const PACKS: { id: Pack; label: string }[] = [
  { id: "storage", label: "Storage" },
  { id: "iam", label: "IAM" },
  { id: "network", label: "Network" },
  { id: "audit", label: "Audit" },
  { id: "relationships", label: "Relationships" },
];

export interface Excerpt {
  firstLine: number;
  lines: string[];
  cited: number[];
}

export interface SourceRef {
  file: string;
  pointer: string;
  line: number | null;
  excerpt: Excerpt | null;
}

export interface EvidenceItem {
  path: string;
  value: string;
}

/** One rule evaluated against one resource. */
export interface CheckResult {
  id: string;
  ruleId: string;
  pack: Pack;
  resourceId: string;
  status: CheckStatus;
  reason: string;
  evidence: EvidenceItem[];
  source: SourceRef | null;
  severity: Severity;
  exceptionId: string | null;
}

export interface Relation {
  kind: string;
  other: string;
  direction: "out" | "in";
}

export interface Resource {
  id: string;
  name: string;
  type: string;
  nativeType: string;
  provider: string;
  region: string;
  supported: boolean;
  source: SourceRef;
  properties: Record<string, unknown>;
  relations: Relation[];
  redacted: string[];
}

export interface Rule {
  id: string;
  pack: Pack;
  title: string;
  severity: Severity;
  providers: string[];
  resourceTypes: string[];
  checks: string;
  notEvaluated: string[];
  remediation: { kind: "auto" | "manual"; detail: string };
}

export interface RuleTest {
  ruleId: string;
  kind: "positive" | "negative" | "boundary" | "other";
  name: string;
  passed: boolean;
}

export interface ExceptionEntry {
  id: string;
  ruleId: string;
  resourceId: string;
  reason: string;
  owner: string;
  ticket: string;
  created: string;
  expires: string;
  state: "active" | "expired" | "rejected" | "not_yet_active";
  problems: string[];
  effect: string;
  inScope: boolean;
  matchesFailing: boolean;
}

export interface RegressionCheck {
  label: string;
  passed: boolean;
  detail: string;
}

export interface Patch {
  id: string;
  resultId: string | null;
  ruleId: string;
  resourceId: string;
  file: string;
  state: "accepted" | "rejected" | "withheld";
  reason: string;
  strategy: string;
  diff: string;
  regression: RegressionCheck[];
}

export interface Summary {
  evaluated: number;
  passed: number;
  failed: number;
  unknown: number;
  excepted: number;
  typesPresent: string[];
  typesCovered: string[];
  uncoveredTypes: string[];
  /** One label per resource no rule evaluated (unsupported types and covered types with no applicable rule). */
  uncovered: string[];
  resourcesPresent: number;
  resourcesEvaluated: number;
  coverageStatement: string;
  completeCoverage: boolean;
}

export interface RunRecordLite {
  runId: string;
  status: string;
  attempt: number;
  createdAt: string;
  completedAt: string | null;
  sourceCommit: string;
  workflowRunId: number | null;
  inputManifestHash: string | null;
  requestSource: { type: string; issue: number | null; actor: string | null };
}

export interface RunModel {
  record: RunRecordLite;
  params: { snapshot: string; rulePacks: Pack[]; remediation: "none" | "propose"; asOf: string };
  provider: string;
  summary: Summary;
  results: CheckResult[];
  resources: Resource[];
  rules: Rule[];
  ruleTests: RuleTest[];
  exceptions: ExceptionEntry[];
  patches: Patch[];
  remediationRequested: boolean;
  tools: Record<string, string>;
  packageVersion: string;
  patchUrl: string | null;
  reportUrl: string;
}

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

export const TYPE_LABELS: Record<string, string> = {
  storage_bucket: "Storage bucket",
  storage_account: "Storage account",
  iam_policy: "IAM policy",
  iam_role: "IAM role",
  iam_user: "IAM user",
  security_group: "Security group",
  network_security_group: "Network security group",
  compute_instance: "Compute instance",
  audit_trail: "Audit trail",
  role_definition: "Role definition",
  role_assignment: "Role assignment",
  diagnostic_setting: "Diagnostic setting",
  unsupported: "Unsupported",
};

export const typeLabel = (t: string) => TYPE_LABELS[t] ?? t.replace(/_/g, " ");
