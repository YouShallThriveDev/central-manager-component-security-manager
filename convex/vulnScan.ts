/**
 * Vulnerability scanning — uses the WPVulnerability.net API (free, no key needed)
 * to check installed plugins against known CVEs.
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
    plugin: string;
    vulnerability: WPVulnEntry[];
  } | null;
}

// ─── Version comparison helpers ──────────────────────────────

function compareVersions(a: string, b: string): number {
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

// ─── Fetch vulnerabilities per slug ──────────────────────────

async function fetchPluginVulns(slug: string): Promise<WPVulnEntry[]> {
  try {
    const url = `https://www.wpvulnerability.net/plugin/${encodeURIComponent(slug)}`;
    const resp = await fetch(url, {
      headers: { "User-Agent": "YST-Security-Manager/1.0" },
    });

    if (!resp.ok) {
      if (resp.status === 429) {
        console.warn(`WPVulnerability rate limited on slug ${slug}, skipping`);
      }
      return [];
    }

    const data = (await resp.json()) as WPVulnResponse;
    if (data.error !== 0 || !data.data?.vulnerability) return [];

    return data.data.vulnerability;
  } catch (e) {
    console.warn(`Failed to fetch vulns for ${slug}:`, e);
    return [];
  }
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
    // Get all sites and their plugins
    const sites: Array<{ _id: string; domain: string }> = (await ctx.runQuery(
      internal.sites.listAll,
      {},
    )) as any;
    if (sites.length === 0) {
      return { sitesScanned: 0, vulnsFound: 0, newVulns: 0, errors: 0 };
    }

    // Collect all unique plugin slugs across all sites with their versions
    const pluginsBySite: Map<
      string,
      Array<{ slug: string; version: string; siteId: string }>
    > = new Map();
    const allSlugs = new Set<string>();

    for (const site of sites) {
      const plugins = await ctx.runQuery(internal.sitePlugins.listAllBySite, {
        siteId: site._id as any,
      });
      const entries: Array<{
        slug: string;
        version: string;
        siteId: string;
      }> = [];
      for (const p of plugins) {
        if (p.version && p.status !== "must-use") {
          allSlugs.add(p.slug);
          entries.push({
            slug: p.slug,
            version: p.version,
            siteId: site._id as string,
          });
        }
      }
      pluginsBySite.set(site._id as string, entries);
    }

    const slugArray = Array.from(allSlugs);

    // Update progress
    await ctx.runMutation(internal.settings.setInternal, {
      key: "vuln_scan_progress",
      value: JSON.stringify({
        status: "scanning",
        phase: "Fetching vulnerability data…",
        total: slugArray.length,
        completed: 0,
      }),
    });

    // Fetch vulnerability data per slug from WPVulnerability.net
    // Process in batches of 5 concurrently to balance speed vs rate limiting
    const vulnsBySlug: Map<string, WPVulnEntry[]> = new Map();
    const batchSize = 5;

    for (let i = 0; i < slugArray.length; i += batchSize) {
      const batch = slugArray.slice(i, i + batchSize);
      const results = await Promise.all(
        batch.map(async (slug) => ({
          slug,
          vulns: await fetchPluginVulns(slug),
        })),
      );

      for (const { slug, vulns } of results) {
        if (vulns.length > 0) {
          vulnsBySlug.set(slug, vulns);
        }
      }

      await ctx.runMutation(internal.settings.setInternal, {
        key: "vuln_scan_progress",
        value: JSON.stringify({
          status: "scanning",
          phase: "Checking plugins…",
          total: slugArray.length,
          completed: Math.min(i + batchSize, slugArray.length),
        }),
      });

      // Small delay between batches
      if (i + batchSize < slugArray.length) {
        await new Promise((resolve) => setTimeout(resolve, 300));
      }
    }

    // Match vulnerabilities to installed plugins on each site
    let vulnsFound = 0;
    let newVulns = 0;
    let errors = 0;

    for (const [siteId, sitePlugins] of pluginsBySite) {
      for (const plugin of sitePlugins) {
        const slugVulns = vulnsBySlug.get(plugin.slug);
        if (!slugVulns) continue;

        // Filter to vulnerabilities that affect this specific version
        const matchingVulns = slugVulns.filter((vuln) =>
          isVersionAffected(plugin.version, vuln.operator),
        );

        for (const vuln of matchingVulns) {
          try {
            // Extract CVE ID from sources
            const cveSource = vuln.source.find((s) =>
              s.id.startsWith("CVE-"),
            );
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
              vuln.source.find((s) =>
                s.link.includes("wordfence.com"),
              )?.link ||
              vuln.source.find((s) =>
                s.link.includes("patchstack.com"),
              )?.link ||
              cveSource?.link ||
              vuln.source[0]?.link;

            // Clean up title (decode HTML entities)
            const title = vuln.name
              .replace(/&#8211;/g, "–")
              .replace(/&lt;/g, "<")
              .replace(/&gt;/g, ">")
              .replace(/&amp;/g, "&")
              .replace(/&#8217;/g, "'");

            const result = await ctx.runMutation(
              internal.vulnerabilities.upsert,
              {
                siteId: siteId as any,
                pluginSlug: plugin.slug,
                pluginVersion: plugin.version,
                cveId,
                title: title.substring(0, 200),
                severity,
                cvssScore: score,
                description: description
                  ? description.substring(0, 1000)
                  : undefined,
                fixedInVersion,
                source: "wpvulnerability",
                sourceUrl,
              },
            );
            vulnsFound++;
            if (result.isNew) newVulns++;
          } catch (e) {
            errors++;
            console.error("Failed to upsert vuln:", e);
          }
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
    }

    // Update progress
    await ctx.runMutation(internal.settings.setInternal, {
      key: "vuln_scan_progress",
      value: JSON.stringify({
        status: "done",
        phase: "Complete",
        total: slugArray.length,
        completed: slugArray.length,
        vulnsFound,
        newVulns,
      }),
    });

    // Log
    await ctx.runMutation(internal.actionLogs.add, {
      action: "vuln_scan",
      details: `Vulnerability scan: ${slugArray.length} plugins checked, ${vulnsFound} vulnerabilities found (${newVulns} new)`,
      status: newVulns > 0 ? "error" : "success",
    });

    // If notify=true (e.g. from cron), schedule Slack notification automatically
    if (args.notify && newVulns > 0) {
      await ctx.scheduler.runAfter(0, internal.vulnScan.notifySlack, {});
    }

    return { sitesScanned: sites.length, vulnsFound, newVulns, errors };
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
          `  • ${v.title} — *${domain}* (${v.pluginSlug} ${v.pluginVersion || ""})${v.fixedInVersion ? ` → Update to ${v.fixedInVersion}` : ""}`,
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
          `  • ${v.title} — *${domain}* (${v.pluginSlug} ${v.pluginVersion || ""})`,
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
