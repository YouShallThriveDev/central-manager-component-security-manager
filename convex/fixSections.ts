/**
 * Sections for Fix on staging actions (Plugins, Themes, Core, Security):
 * run order, grouping and per-section counts. Pure — no Convex imports — so
 * the dialog can use it too and it can be tested directly.
 *
 * Run and display order: plugins, then themes, then WordPress core last (so
 * plugin/theme compatibility updates land before core moves), then Security
 * (Wordfence activation). Within a section, vulnerability fixes come first.
 */

export type Section = "plugins" | "themes" | "core" | "security";

export const SECTIONS: Section[] = ["plugins", "themes", "core", "security"];

export const SECTION_LABEL: Record<Section, string> = {
  plugins: "Plugins",
  themes: "Themes",
  core: "Core",
  security: "Security",
};

type ActionLike = {
  kind: string;
  slug: string;
  name?: string;
  status: string;
  fixedIn?: string;
  vuln?: boolean;
  fromVersion?: string;
};

export const sectionOf = (kind: string): Section =>
  kind === "update_theme"
    ? "themes"
    : kind === "update_core"
      ? "core"
      : kind === "activate_wordfence"
        ? "security"
        : "plugins";

/** Planned because of an open vulnerability (older rows only have fixedIn). */
export const isVulnFix = (a: ActionLike) => !!a.vuln || !!a.fixedIn;

function cmp(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** An open vulnerability this update is meant to fix (not one staging
 *  already has the fix for). */
export const fixesVuln = (a: ActionLike) =>
  isVulnFix(a) &&
  !(a.fixedIn && a.fromVersion && cmp(a.fromVersion, a.fixedIn) >= 0);

/** Section order, vulnerability fixes first, then by name. */
export function orderActions<T extends ActionLike>(actions: T[]): T[] {
  const label = (a: T) => (a.name ?? a.slug).toLowerCase();
  return [...actions].sort(
    (a, b) =>
      SECTIONS.indexOf(sectionOf(a.kind)) -
        SECTIONS.indexOf(sectionOf(b.kind)) ||
      Number(isVulnFix(b)) - Number(isVulnFix(a)) ||
      label(a).localeCompare(label(b)),
  );
}

export type SectionGroup<T> = {
  section: Section;
  label: string;
  actions: T[];
};

/** Actions grouped by section, in section order; empty sections omitted. */
export function groupBySection<T extends ActionLike>(
  actions: T[],
): SectionGroup<T>[] {
  return SECTIONS.map(section => ({
    section,
    label: SECTION_LABEL[section],
    actions: actions.filter(a => sectionOf(a.kind) === section),
  })).filter(g => g.actions.length > 0);
}

/**
 * Per-section counts, e.g. "12 updated, 2 skipped" (run) or
 * "12 planned, 3 for vulnerabilities" (plan). Core and Security hold a
 * single action whose own status is shown, so they get no counts.
 */
export function sectionSummary<T extends ActionLike>(
  group: SectionGroup<T>,
  mode: "plan" | "run",
): string | undefined {
  if (group.section === "core" || group.section === "security")
    return undefined;
  const { actions } = group;
  if (mode === "plan") {
    const v = actions.filter(isVulnFix).length;
    return `${actions.length} planned${v ? `, ${v} for vulnerabilities` : ""}`;
  }
  const n = (s: string) => actions.filter(a => a.status === s).length;
  return [
    [n("done"), "updated"],
    [n("needs_check"), "need check"],
    [n("failed"), "failed"],
    [n("skipped"), "skipped"],
    [n("pending"), "pending"],
  ]
    .filter(([c]) => (c as number) > 0)
    .map(([c, w]) => `${c} ${w}`)
    .join(", ");
}
