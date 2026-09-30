import { v } from "convex/values";
import { internalMutation, type MutationCtx } from "./_generated/server";
import type { Id } from "./_generated/dataModel";

export type Grade = "A" | "B" | "C" | "D" | "F";
type Severity = "critical" | "high" | "medium" | "low";

const VULN_WEIGHTS: Record<Severity, number> = { critical: 25, high: 10, medium: 4, low: 1 };
const MAX_VULN_PENALTY = 60;
const GRADE_ORDER: Grade[] = ["A", "B", "C", "D", "F"];

export type ScoreFeatures = {
  hasFirewall?: boolean;
  hasMalwareScanner?: boolean;
  hasBackup?: boolean;
  hasTwoFactor?: boolean;
  hasBruteForceProtection?: boolean;
  pluginsNeedingUpdate?: number;
  totalPlugins?: number;
  sslEnabled?: boolean;
  wordfenceActive?: boolean;
  wordfenceInstalled?: boolean;
};

export type VulnCounts = Record<Severity, number>;

const gradeFromScore = (score: number): Grade =>
  score >= 85 ? "A" : score >= 70 ? "B" : score >= 50 ? "C" : score >= 30 ? "D" : "F";

export function baseScore(f: ScoreFeatures): number {
  let score = 0;
  if (f.hasFirewall) score += 25;
  if (f.hasMalwareScanner) score += 15;
  if (f.hasBackup) score += 15;
  if (f.hasTwoFactor) score += 10;
  if (f.hasBruteForceProtection) score += 5;
  if (f.sslEnabled) score += 10;
  if (f.wordfenceActive) score += 5;
  else if (f.wordfenceInstalled) score -= 3;
  const total = f.totalPlugins ?? 0;
  if (total > 0) {
    const r = (f.pluginsNeedingUpdate ?? 0) / total;
    score += r === 0 ? 15 : r < 0.05 ? 12 : r < 0.1 ? 8 : r < 0.25 ? 4 : 0;
  } else {
    score += 15;
  }
  return Math.max(0, Math.min(100, score));
}

export function calculateSecurityScore(f: ScoreFeatures, vulns: VulnCounts) {
  const base = baseScore(f);
  const vulnPenalty = Math.min(
    MAX_VULN_PENALTY,
    (Object.keys(VULN_WEIGHTS) as Severity[]).reduce((s, k) => s + vulns[k] * VULN_WEIGHTS[k], 0),
  );
  const score = Math.max(0, base - vulnPenalty);
  const gradeCap: Grade | undefined =
    vulns.critical > 0 ? "D" : vulns.high > 0 ? "C" : vulns.medium + vulns.low > 0 ? "B" : undefined;
  let grade = gradeFromScore(score);
  if (gradeCap && GRADE_ORDER.indexOf(grade) < GRADE_ORDER.indexOf(gradeCap)) grade = gradeCap;
  return { score, grade, baseScore: base, vulnPenalty, gradeCap };
}

export async function countOpenVulns(ctx: MutationCtx, siteId: Id<"sites">): Promise<VulnCounts> {
  const counts: VulnCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  const vulns = await ctx.db
    .query("vulnerabilities")
    .withIndex("by_site", (q) => q.eq("siteId", siteId))
    .collect();
  for (const x of vulns) if (x.status === "open") counts[x.severity]++;
  return counts;
}

export async function recalcSiteScore(ctx: MutationCtx, siteId: Id<"sites">) {
  const site = await ctx.db.get(siteId);
  if (!site) return null;
  const counts = await countOpenVulns(ctx, siteId);
  const r = calculateSecurityScore(site, counts);
  await ctx.db.patch(siteId, {
    securityScore: r.score,
    securityGrade: r.grade,
    securityBaseScore: r.baseScore,
    vulnPenalty: r.vulnPenalty,
    vulnGradeCap: r.gradeCap,
    openVulnCritical: counts.critical,
    openVulnHigh: counts.high,
    openVulnMedium: counts.medium,
    openVulnLow: counts.low,
  });
  return r;
}

export const recalcSite = internalMutation({
  args: { siteId: v.id("sites") },
  returns: v.null(),
  handler: async (ctx, args) => {
    await recalcSiteScore(ctx, args.siteId);
    return null;
  },
});

export const recalcAll = internalMutation({
  args: {},
  returns: v.object({ sites: v.number(), changed: v.number() }),
  handler: async (ctx) => {
    const sites = await ctx.db.query("sites").collect();
    let changed = 0;
    for (const s of sites) {
      const r = await recalcSiteScore(ctx, s._id);
      if (r && (r.score !== s.securityScore || r.grade !== s.securityGrade)) changed++;
    }
    return { sites: sites.length, changed };
  },
});
