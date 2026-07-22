/**
 * Vulnerability scanning — uses the Wordfence Intelligence API (free, no key needed)
 * to check installed plugins against known vulnerabilities.
 *
 * API docs: https://www.wordfence.com/help/wordfence-intelligence-api/
 */
import { v } from "convex/values";
import { action, internalAction } from "./_generated/server";
import { internal } from "./_generated/api";

declare const process: { env: Record<string, string | undefined> };

type Severity = "critical" | "high" | "medium" | "low";

interface WorDefenceVuln {
  id: string;
  title: string;
  software: Array<{
    type: string;
    slug: string;
    affected_versions: Record<
      string,
      {
        from_version: string;
        to_version: string;
      }
    >;
    patched_versions?: string[];
  }>;
  cve?: string;
  cvss?: {
    score: number;
    vector: string;
  };
  description?: string;
  references?: string[];
  published?: string;
}

function cvssToSeverity(score: number): Severity {
  if (score >= 9.0) return "critical";
  if (score >= 7.0) return "high";
  if (score >= 4.0) return "medium";
  return "low";
}

function isVersionAffected(
  version: string,
  from: string,
  to: string,
): boolean {
  const v = version.split(".").map(Number);
  const f = from === "*" ? null : from.split(".").map(Number);
  const t = to === "*" ? null : to.split(".").map(Number);

  if (f) {
    for (let i = 0; i < Math.max(v.length, f.length); i++) {
      const va = v[i] ?? 0;
      const fa = f[i] ?? 0;
      if (va < fa) return false;
      if (va > fa) break;
    }
  }

  if (t) {
    for (let i = 0; i < Math.max(v.length, t.length); i++) {
      const va = v[i] ?? 0;
      const ta = t[i] ?? 0;
      if (va > ta) return false;
      if (va < ta) break;
    }
  }

  return true;
}

// Batch fetch vulnerabilities for multiple plugin slugs from Wordfence Intelligence
async function fetchWordfenceVulns(
  slugs: string[],
): Promise<WorDefenceVuln[]> {
  const allVulns: WorDefenceVuln[] = [];

  // Wordfence Intelligence API — scan endpoint
  // We query in batches of slugs to be respectful of rate limits
  for (const slug of slugs) {
    try {
      const url = `https://www.wordfence.com/api/intelligence/v2/vulnerabilities/production?software_type=plugin&software_slug=${encodeURIComponent(slug)}`;
      const resp = await fetch(url, {
        headers: { "User-Agent": "YST-Security-Manager/1.0" },
      });

      if (!resp.ok) {
        if (resp.status === 429) {
          // Rate limited — wait and skip this batch
          console.warn(`Wordfence rate limited on slug ${slug}, skipping`);
          continue;
        }
        continue;
      }

      const data = (await resp.json()) as Record<string, WorDefenceVuln>;

      // The API returns a map of vuln_id -> vuln object
      for (const vuln of Object.values(data)) {
        allVulns.push(vuln);
      }
    } catch (e) {
      console.warn(`Failed to fetch vulns for ${slug}:`, e);
    }
  }

  return allVulns;
}

// ─── Scan Action ─────────────────────────────────────────────

export const scanAllSites = action({
  args: {},
  returns: v.object({
    sitesScanned: v.number(),
    vulnsFound: v.number(),
    newVulns: v.number(),
    errors: v.number(),
  }),
  handler: async (ctx): Promise<{ sitesScanned: number; vulnsFound: number; newVulns: number; errors: number }> => {
    // Get all sites and their plugins
    const sites: Array<{ _id: string; domain: string }> = await ctx.runQuery(internal.sites.listAll, {}) as any;
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

    // Fetch vulnerabilities from Wordfence for all unique slugs
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

    // Scan in batches of 10 to avoid rate limiting
    const allVulns: WorDefenceVuln[] = [];
    const batchSize = 10;
    for (let i = 0; i < slugArray.length; i += batchSize) {
      const batch = slugArray.slice(i, i + batchSize);
      const vulns = await fetchWordfenceVulns(batch);
      allVulns.push(...vulns);

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
        await new Promise((resolve) => setTimeout(resolve, 200));
      }
    }

    // Match vulnerabilities to installed plugins on each site
    let vulnsFound = 0;
    let newVulns = 0;
    let errors = 0;

    for (const [siteId, sitePlugins] of pluginsBySite) {
      for (const plugin of sitePlugins) {
        // Find matching vulnerabilities for this plugin
        const matchingVulns = allVulns.filter((vuln) => {
          return vuln.software?.some((sw) => {
            if (sw.slug !== plugin.slug) return false;
            // Check if this version is in affected range
            for (const range of Object.values(sw.affected_versions || {})) {
              if (
                isVersionAffected(
                  plugin.version,
                  range.from_version,
                  range.to_version,
                )
              ) {
                return true;
              }
            }
            return false;
          });
        });

        for (const vuln of matchingVulns) {
          try {
            const sw = vuln.software?.find((s) => s.slug === plugin.slug);
            const fixedIn =
              sw?.patched_versions?.length ? sw.patched_versions[0] : undefined;

            const result = await ctx.runMutation(
              internal.vulnerabilities.upsert,
              {
                siteId: siteId as any,
                pluginSlug: plugin.slug,
                pluginVersion: plugin.version,
                cveId: vuln.cve || undefined,
                title: vuln.title || `Vulnerability in ${plugin.slug}`,
                severity: vuln.cvss
                  ? cvssToSeverity(vuln.cvss.score)
                  : "medium",
                cvssScore: vuln.cvss?.score,
                description: vuln.description
                  ? vuln.description.substring(0, 1000)
                  : undefined,
                fixedInVersion: fixedIn,
                source: "wordfence",
                sourceUrl: vuln.references?.length
                  ? vuln.references[0]
                  : `https://www.wordfence.com/threat-intel/vulnerabilities/id/${vuln.id}`,
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
    }> = await ctx.runQuery(
      internal.vulnerabilities.listUnnotified,
      {},
    ) as any;
    if (unnotified.length === 0) return { notified: 0 };

    // Get site domains for context
    const sites: Array<{ _id: string; domain: string }> = await ctx.runQuery(internal.sites.listAll, {}) as any;
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
    lines.push(
      `📊 View all details in Security Manager dashboard`,
    );

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
