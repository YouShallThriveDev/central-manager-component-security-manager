/**
 * Vulnerability scanning — uses the WPVulnerability.net API (free, no key needed)
 * to check installed plugins and themes against known CVEs.
 *
 * API docs: https://www.wpvulnerability.net/
 * Migrated from Wordfence Intelligence API v2 (deprecated/removed July 2026).
 */
import { v } from "convex/values";
import { action, internalAction } from "./_generated/server";
import { internal } from "./_generated/api";

declare const process: { env: Record<string, string | undefined> };

type Severity = "critical" | "high" | "medium" | "low";

// ─── WPVulnerability.net response types ──────────────────────

interface WPVulnOperator {
  min_version: string | null;
  min_operator: string | null; // "gt", "gte", null
  max_version: string | null;
  max_operator: string | null; // "lt", "lte", null
  unfixed: string; // "0" or "1"
  closed: string;
}

interface WPVulnSource {
  id: string;
  name: string;
  link: string;
  description: string | null;
  date: string | null;
}

interface WPVulnImpact {
  cvss?: { score: string; severity: string };
  cvss3?: { score: string; severity: string };
}

interface WPVulnEntry {
  uuid: string;
  name: string;
  description: string | null;
  operator: WPVulnOperator;
  source: WPVulnSource[];
  impact?: WPVulnImpact;
}

interface WPVulnResponse {
  error: number;
  data: {
    name: string;
    vulnerability: WPVulnEntry[];
  } | null;
}

// ─── Version comparison helpers ──────────────────────────────

export function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const va = pa[i] ?? 0;
    const vb = pb[i] ?? 0;
    if (va < vb) return -1;
    if (va > vb) return 1;
  }
  return 0;
}

function isVersionAffected(version: string, op: WPVulnOperator): boolean {
  // Check minimum version constraint
  if (op.min_version) {
    const cmp = compareVersions(version, op.min_version);
    if (op.min_operator === "gt" && cmp <= 0) return false;
    if (op.min_operator === "gte" && cmp < 0) return false;
    // If no operator specified, treat as >=
    if (!op.min_operator && cmp < 0) return false;
  }

  // Check maximum version constraint
  if (op.max_version) {
    const cmp = compareVersions(version, op.max_version);
    if (op.max_operator === "lt" && cmp >= 0) return false;
    if (op.max_operator === "lte" && cmp > 0) return false;
    // If no operator specified, treat as <
    if (!op.max_operator && cmp >= 0) return false;
  }

  return true;
}

function severityFromImpact(impact?: WPVulnImpact): { severity: Severity; score: number | undefined } {
  const cvss = impact?.cvss3 || impact?.cvss;
  if (!cvss) return { severity: "medium", score: undefined };

  const score = parseFloat(cvss.score);
  if (isNaN(score)) return { severity: "medium", score: undefined };

  let severity: Severity;
  if (score >= 9.0) severity = "critical";
  else if (score >= 7.0) severity = "high";
  else if (score >= 4.0) severity = "medium";
  else severity = "low";

  return { severity, score };
}

// ─── Fetch vulnerabilities per component ─────────────────────

type ComponentType = "plugin" | "theme";

/** One installed plugin or theme on one site. */
type Component = { type: ComponentType; slug: string; version: string };

const componentKey = (c: { type: ComponentType; slug: string }) =>
  `${c.type}:${c.slug}`;

// Same API and response shape for both; the official WPVulnerability client
// builds `${host}${type}/${slug}/` with type "plugin" | "theme" | "core".
export function wpvulnUrl(type: ComponentType, slug: string): string {
  const s = encodeURIComponent(slug);
  return type === "theme"
    ? `https://www.wpvulnerability.net/theme/${s}/`
    : `https://www.wpvulnerability.net/plugin/${s}`;
}

async function fetchComponentVulns(
  type: ComponentType,
  slug: string,
): Promise<WPVulnEntry[]> {
  try {
    const resp = await fetch(wpvulnUrl(type, slug), {
      headers: { "User-Agent": "YST-Security-Manager/1.0" },
    });

    if (!resp.ok) {
      if (resp.status === 429) {
        console.warn(`WPVulnerability rate limited on ${type} ${slug}, skipping`);
      }
      return [];
    }

    const data = (await resp.json()) as WPVulnResponse;
    if (data.error !== 0 || !data.data?.vulnerability) return [];

    return data.data.vulnerability;
  } catch (e) {
    console.warn(`Failed to fetch vulns for ${type} ${slug}:`, e);
    return [];
  }
}

/** Fetch vulnerability data for each component, 5 at a time. */
async function fetchVulnsFor(
  components: Array<{ type: ComponentType; slug: string }>,
  onBatch?: (completed: number) => Promise<unknown>,
): Promise<Map<string, WPVulnEntry[]>> {
  const vulnsByKey: Map<string, WPVulnEntry[]> = new Map();
  const batchSize = 5;
  for (let i = 0; i < components.length; i += batchSize) {
    const batch = components.slice(i, i + batchSize);
    const results = await Promise.all(
      batch.map(async (c) => ({
        key: componentKey(c),
        vulns: await fetchComponentVulns(c.type, c.slug),
      })),
    );
    for (const { key, vulns } of results) {
      if (vulns.length > 0) vulnsByKey.set(key, vulns);
    }
    await onBatch?.(Math.min(i + batchSize, components.length));
    // Small delay between batches
    if (i + batchSize < components.length) {
      await new Promise((resolve) => setTimeout(resolve, 300));
    }
  }
  return vulnsByKey;
}

/** Installed plugins (not must-use) and themes with a known version. */
async function siteComponents(
  ctx: { runQuery: (ref: any, args: any) => Promise<any> },
  siteId: string,
): Promise<Component[]> {
  const plugins: Array<{ slug: string; version?: string; status: string }> =
    await ctx.runQuery(internal.sitePlugins.listAllBySite, {
      siteId: siteId as any,
    });
  const themes: Array<{ slug: string; version?: string }> =
    await ctx.runQuery(internal.siteThemes.listAllBySite, {
      siteId: siteId as any,
    });
  const out: Component[] = [];
  for (const p of plugins) {
    if (p.version && p.status !== "must-use") {
      out.push({ type: "plugin", slug: p.slug, version: p.version });
    }
  }
  for (const t of themes) {
    if (t.version) out.push({ type: "theme", slug: t.slug, version: t.version });
  }
  return out;
}

/** Unique components across sites, in first-seen order. */
function uniqueComponents(lists: Component[][]) {
  const seen = new Map<string, { type: ComponentType; slug: string }>();
  for (const list of lists) {
    for (const c of list) {
      if (!seen.has(componentKey(c))) seen.set(componentKey(c), { type: c.type, slug: c.slug });
    }
  }
  return [...seen.values()];
}

/** The vulnerabilities.upsert fields for one WPVulnerability entry. */
function vulnRecord(vuln: WPVulnEntry) {
  // Extract CVE ID from sources
  const cveSource = vuln.source.find((s) => s.id.startsWith("CVE-"));
  const cveId = cveSource?.id;

  // Get description from the best source
  const description =
    cveSource?.description ||
    vuln.source.find((s) => s.description)?.description ||
    vuln.description;

  // Get severity and score
  const { severity, score } = severityFromImpact(vuln.impact);

  // Determine fixed version from operator
  const fixedInVersion =
    vuln.operator.unfixed === "0" && vuln.operator.max_version
      ? vuln.operator.max_version
      : undefined;

  // Get source URL (prefer Wordfence, then Patchstack, then CVE link)
  const sourceUrl =
    vuln.source.find((s) => s.link.includes("wordfence.com"))?.link ||
    vuln.source.find((s) => s.link.includes("patchstack.com"))?.link ||
    cveSource?.link ||
    vuln.source[0]?.link;

  // Clean up title (decode HTML entities)
  const title = vuln.name
    .replace(/&#8211;/g, "–")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&")
    .replace(/&#8217;/g, "'");

  return {
    cveId,
    title: title.substring(0, 200),
    severity,
    cvssScore: score,
    description: description ? description.substring(0, 1000) : undefined,
    fixedInVersion,
    source: "wpvulnerability",
    sourceUrl,
  };
}

/** Upsert every vulnerability affecting one installed component. */
async function recordComponentVulns(
  ctx: { runMutation: (ref: any, args: any) => Promise<any> },
  siteId: string,
  c: Component,
  vulnsByKey: Map<string, WPVulnEntry[]>,
): Promise<{ found: number; added: number; errors: number }> {
  const r = { found: 0, added: 0, errors: 0 };
  const entries = vulnsByKey.get(componentKey(c));
  if (!entries) return r;

  // Filter to vulnerabilities that affect this specific version
  for (const vuln of entries.filter((x) => isVersionAffected(c.version, x.operator))) {
    try {
      const result = await ctx.runMutation(internal.vulnerabilities.upsert, {
        siteId: siteId as any,
        ...(c.type === "theme" ? { componentType: "theme" } : {}),
        pluginSlug: c.slug,
        pluginVersion: c.version,
        ...vulnRecord(vuln),
      });
      r.found++;
      if (result.isNew) r.added++;
    } catch (e) {
      r.errors++;
      console.error("Failed to upsert vuln:", e);
    }
  }
  return r;
}

// ─── Scan Action ─────────────────────────────────────────────

export const scanAllSites = action({
  args: {
    notify: v.optional(v.boolean()),
  },
  returns: v.object({
    sitesScanned: v.number(),
    vulnsFound: v.number(),
    newVulns: v.number(),
    errors: v.number(),
  }),
  handler: async (ctx, args): Promise<{
    sitesScanned: number;
    vulnsFound: number;
    newVulns: number;
    errors: number;
  }> => {
    // Get all sites and their plugins + themes
    const sites: Array<{ _id: string; domain: string }> = (await ctx.runQuery(
      internal.sites.listAll,
      {},
    )) as any;
    if (sites.length === 0) {
      return { sitesScanned: 0, vulnsFound: 0, newVulns: 0, errors: 0 };
    }

    const componentsBySite: Map<string, Component[]> = new Map();
    for (const site of sites) {
      componentsBySite.set(site._id, await siteComponents(ctx, site._id));
    }
    const unique = uniqueComponents([...componentsBySite.values()]);
    const pluginCount = unique.filter((c) => c.type === "plugin").length;
    const themeCount = unique.length - pluginCount;

    const progress = (status: string, phase: string, completed: number, extra = {}) =>
      ctx.runMutation(internal.settings.setInternal, {
        key: "vuln_scan_progress",
        value: JSON.stringify({ status, phase, total: unique.length, completed, ...extra }),
      });

    await progress("scanning", "Fetching vulnerability data…", 0);

    // Fetch vulnerability data per plugin/theme slug from WPVulnerability.net
    const vulnsByKey = await fetchVulnsFor(unique, (completed) =>
      progress("scanning", "Checking plugins and themes…", completed),
    );

    // Match vulnerabilities to installed plugins and themes on each site
    let vulnsFound = 0;
    let newVulns = 0;
    let errors = 0;

    for (const [siteId, components] of componentsBySite) {
      for (const c of components) {
        const r = await recordComponentVulns(ctx, siteId, c, vulnsByKey);
        vulnsFound += r.found;
        newVulns += r.added;
        errors += r.errors;
      }
      // Auto-resolve patched vulnerabilities
      try {
        await ctx.runMutation(internal.vulnerabilities.autoResolvePatched, {
          siteId: siteId as any,
        });
      } catch {
        // non-critical
      }
    }

    await progress("done", "Complete", unique.length, { vulnsFound, newVulns });

    // Log
    await ctx.runMutation(internal.actionLogs.add, {
      action: "vuln_scan",
      details: `Vulnerability scan: ${pluginCount} plugins and ${themeCount} themes checked, ${vulnsFound} vulnerabilities found (${newVulns} new)`,
      status: newVulns > 0 ? "error" : "success",
    });

    // If notify=true (e.g. from cron), schedule Slack notification automatically
    if (args.notify && newVulns > 0) {
      await ctx.scheduler.runAfter(0, internal.vulnScan.notifySlack, {});
    }

    return { sitesScanned: sites.length, vulnsFound, newVulns, errors };
  },
});

// ─── Single-Site Rescan Action ───────────────────────────────

export const rescanSite = action({
  args: {
    siteId: v.id("sites"),
  },
  returns: v.object({
    vulnsFound: v.number(),
    newVulns: v.number(),
    resolved: v.number(),
    pluginsChecked: v.number(),
    themesChecked: v.number(),
  }),
  handler: async (ctx, args): Promise<{
    vulnsFound: number;
    newVulns: number;
    resolved: number;
    pluginsChecked: number;
    themesChecked: number;
  }> => {
    const components = await siteComponents(ctx, args.siteId);
    const unique = uniqueComponents([components]);
    const vulnsByKey = await fetchVulnsFor(unique);

    // Match vulnerabilities to installed plugins and themes
    let vulnsFound = 0;
    let newVulns = 0;
    for (const c of components) {
      const r = await recordComponentVulns(ctx, args.siteId, c, vulnsByKey);
      vulnsFound += r.found;
      newVulns += r.added;
    }

    // Auto-resolve patched vulnerabilities for this site
    const resolveResult: { resolved: number } = await ctx.runMutation(
      internal.vulnerabilities.autoResolvePatched,
      { siteId: args.siteId },
    ) as any;

    const pluginsChecked = unique.filter((c) => c.type === "plugin").length;
    return {
      vulnsFound,
      newVulns,
      resolved: resolveResult.resolved,
      pluginsChecked,
      themesChecked: unique.length - pluginsChecked,
    };
  },
});

// ─── Slack Notification Action ───────────────────────────────

export const notifySlack = internalAction({
  args: {},
  returns: v.object({ notified: v.number() }),
  handler: async (ctx): Promise<{ notified: number }> => {
    // Get unnotified vulnerabilities
    const unnotified: Array<{
      _id: string;
      siteId: string;
      componentType?: "plugin" | "theme";
      pluginSlug: string;
      pluginVersion?: string;
      cveId?: string;
      title: string;
      severity: string;
      cvssScore?: number;
      fixedInVersion?: string;
      slackNotified: boolean;
    }> = (await ctx.runQuery(
      internal.vulnerabilities.listUnnotified,
      {},
    )) as any;
    if (unnotified.length === 0) return { notified: 0 };

    // Get site domains for context
    const sites: Array<{ _id: string; domain: string }> = (await ctx.runQuery(
      internal.sites.listAll,
      {},
    )) as any;
    const siteDomains: Record<string, string> = {};
    for (const site of sites) {
      siteDomains[site._id] = site.domain;
    }

    // Group by severity
    const critical = unnotified.filter((v) => v.severity === "critical");
    const high = unnotified.filter((v) => v.severity === "high");
    const medLow = unnotified.filter(
      (v) => v.severity === "medium" || v.severity === "low",
    );

    // Build notification text
    const lines: string[] = [];
    lines.push(
      `🚨 *Security Alert: ${unnotified.length} New Vulnerabilities Detected*`,
    );
    lines.push("");

    if (critical.length > 0) {
      lines.push(`🔴 *Critical (${critical.length}):*`);
      for (const v of critical.slice(0, 5)) {
        const domain = siteDomains[v.siteId as string] || "Unknown";
        lines.push(
          `  • ${v.title} — *${domain}* (${v.componentType === "theme" ? "theme " : ""}${v.pluginSlug} ${v.pluginVersion || ""})${v.fixedInVersion ? ` → Update to ${v.fixedInVersion}` : ""}`,
        );
      }
      if (critical.length > 5)
        lines.push(`  …and ${critical.length - 5} more`);
      lines.push("");
    }

    if (high.length > 0) {
      lines.push(`🟠 *High (${high.length}):*`);
      for (const v of high.slice(0, 5)) {
        const domain = siteDomains[v.siteId as string] || "Unknown";
        lines.push(
          `  • ${v.title} — *${domain}* (${v.componentType === "theme" ? "theme " : ""}${v.pluginSlug} ${v.pluginVersion || ""})`,
        );
      }
      if (high.length > 5) lines.push(`  …and ${high.length - 5} more`);
      lines.push("");
    }

    if (medLow.length > 0) {
      lines.push(
        `🟡 Medium/Low: ${medLow.length} additional vulnerabilities`,
      );
    }

    lines.push("");
    lines.push(`📊 <https://security-manager-0bf78f18.viktor.space|View all details in Security Manager dashboard>`);

    // Send via Viktor Tools
    const apiUrl = process.env.VIKTOR_SPACES_API_URL;
    const secret = process.env.VIKTOR_SPACES_PROJECT_SECRET;
    const projectName = process.env.VIKTOR_SPACES_PROJECT_NAME;

    if (apiUrl && secret && projectName) {
      try {
        const resp = await fetch(`${apiUrl}/api/viktor-spaces/tools/call`, {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
          },
          body: JSON.stringify({
            project_name: projectName,
            project_secret: secret,
            role: "coworker_send_slack_message",
            arguments: {
              channel_id: "C0B0WHH2L8M", // #central-server-site-mgmt-dash
              blocks: [
                {
                  type: "section",
                  text: {
                    type: "mrkdwn",
                    text: lines.join("\n"),
                  },
                },
              ],
              do_send: true,
            },
          }),
        });

        if (!resp.ok) {
          console.error("Slack notification failed:", await resp.text());
        }
      } catch (e) {
        console.error("Failed to send Slack notification:", e);
      }
    }

    // Mark all as notified
    await ctx.runMutation(internal.vulnerabilities.markNotified, {
      ids: unnotified.map((v) => v._id) as any,
    });

    return { notified: unnotified.length };
  },
});
