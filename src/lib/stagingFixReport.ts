/**
 * Labels and the plain-text report for Fix on staging, grouped into the
 * sections from convex/fixSections.ts. Pure, so it can be tested directly.
 */
import {
  fixesVuln,
  groupBySection,
  isVulnFix,
  sectionSummary,
} from "../../convex/fixSections";

export type FixAction = {
  kind: "update_plugin" | "activate_wordfence" | "update_theme" | "update_core";
  slug: string;
  name?: string;
  fixedIn?: string;
  vuln?: boolean;
  offered?: string;
  status: "pending" | "done" | "failed" | "skipped" | "needs_check";
  fromVersion?: string;
  toVersion?: string;
  prodVersion?: string;
  note?: string;
  reason?: string;
  detail?: string;
  tone?: "attention" | "ok";
  covers?: string[];
};

export type ReportJob = {
  _creationTime: number;
  status: "running" | "done";
  items: {
    domain: string;
    stagingSiteId?: number;
    status: string;
    error?: string;
    actions: FixAction[];
  }[];
};

export const statusLabel = (status: string) => status.replace(/_/g, " ");

/** Name shown inside a section (the section says what kind it is). */
export const actionLabel = (a: FixAction) =>
  a.kind === "activate_wordfence"
    ? "Activate Wordfence"
    : a.kind === "update_core"
      ? "WordPress"
      : (a.name ?? a.slug);

/** Target version: what staging ended on, else what's offered (not for
 *  skipped items, which didn't move). */
export const targetVersion = (a: FixAction) =>
  a.toVersion ?? (a.status === "skipped" ? undefined : a.offered);

export const coversText = (a: FixAction) =>
  a.covers?.length ? `covers bundled ${a.covers.join(", ")}` : undefined;

/** "fixes vulnerability, fixed in 11.1.0" and similar. */
export function vulnText(a: FixAction): string | undefined {
  if (!isVulnFix(a)) return undefined;
  if (!fixesVuln(a))
    return a.fixedIn ? `vulnerability fixed in ${a.fixedIn}` : undefined;
  return a.fixedIn
    ? `fixes vulnerability, fixed in ${a.fixedIn}`
    : "open vulnerability, no fixed version released";
}

const indent = (pad: string, label: string, text: string) =>
  `${pad}${label}: ${text.trim().split("\n").join(`\n${pad}  `)}`;

function actionLine(a: FixAction): string {
  const versions =
    a.kind === "activate_wordfence"
      ? ""
      : [a.fromVersion, targetVersion(a)].filter(Boolean).join(" → ");
  const extra = [
    vulnText(a),
    coversText(a),
    a.prodVersion &&
      a.fromVersion &&
      a.prodVersion !== a.fromVersion &&
      `live ${a.prodVersion}`,
  ]
    .filter(Boolean)
    .join(", ");
  const why = a.reason ?? a.note;
  return `  - ${actionLabel(a)}${versions ? ` ${versions}` : ""}: ${statusLabel(a.status)}${extra ? ` (${extra})` : ""}${why ? ` — ${why}` : ""}`;
}

/** Plain-text report of a job, for pasting into Asana. */
export function jobReport(job: ReportJob, when?: string): string {
  const lines = [
    `Fix on staging — ${when ?? new Date(job._creationTime).toLocaleString()} — ${job.status === "running" ? "running" : "finished"}`,
  ];
  for (const i of job.items) {
    lines.push(
      "",
      `${i.domain}${i.stagingSiteId ? ` (staging #${i.stagingSiteId})` : ""} — ${statusLabel(i.status)}`,
    );
    if (i.error)
      lines.push(
        indent("  ", i.status === "skipped" ? "Reason" : "Error", i.error),
      );
    if (i.status === "skipped") continue;
    for (const g of groupBySection(i.actions)) {
      const counts = sectionSummary(g, "run");
      lines.push(`  ${g.label}${counts ? ` (${counts})` : ""}`);
      for (const a of g.actions) {
        lines.push(actionLine(a));
        if (a.detail) lines.push(indent("    ", "Detail", a.detail));
      }
    }
  }
  return lines.join("\n");
}
