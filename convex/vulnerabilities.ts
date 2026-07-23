/**
 * Vulnerability alerts — queries, mutations, and scanning actions.
 * Uses the free Wordfence Intelligence API to check for known plugin vulnerabilities.
 */
import { v } from "convex/values";
import {
  query,
  mutation,
  internalMutation,
  internalQuery,
} from "./_generated/server";

const severityValidator = v.union(
  v.literal("critical"),
  v.literal("high"),
  v.literal("medium"),
  v.literal("low"),
);

const statusValidator = v.union(
  v.literal("open"),
  v.literal("patched"),
  v.literal("dismissed"),
);

const vulnReturnValidator = v.object({
  _id: v.id("vulnerabilities"),
  _creationTime: v.number(),
  siteId: v.id("sites"),
  pluginSlug: v.string(),
  pluginVersion: v.optional(v.string()),
  cveId: v.optional(v.string()),
  title: v.string(),
  severity: severityValidator,
  cvssScore: v.optional(v.number()),
  description: v.optional(v.string()),
  fixedInVersion: v.optional(v.string()),
  source: v.string(),
  sourceUrl: v.optional(v.string()),
  status: statusValidator,
  firstDetectedAt: v.number(),
  resolvedAt: v.optional(v.number()),
  slackNotified: v.boolean(),
});

// ─── Queries ──────────────────────────────────────────────────

export const list = query({
  args: {
    status: v.optional(v.string()),
    severity: v.optional(v.string()),
    siteId: v.optional(v.id("sites")),
    limit: v.optional(v.number()),
  },
  returns: v.array(vulnReturnValidator),
  handler: async (ctx, args) => {
    let vulns;

    if (args.siteId) {
      vulns = await ctx.db
        .query("vulnerabilities")
        .withIndex("by_site", (q) => q.eq("siteId", args.siteId!))
        .collect();
    } else if (
      args.status &&
      (args.status === "open" ||
        args.status === "patched" ||
        args.status === "dismissed")
    ) {
      vulns = await ctx.db
        .query("vulnerabilities")
        .withIndex("by_status", (q) =>
          q.eq("status", args.status as "open" | "patched" | "dismissed"),
        )
        .collect();
    } else {
      vulns = await ctx.db.query("vulnerabilities").collect();
    }

    if (
      args.severity &&
      args.severity !== "all" &&
      (args.severity === "critical" ||
        args.severity === "high" ||
        args.severity === "medium" ||
        args.severity === "low")
    ) {
      vulns = vulns.filter((v) => v.severity === args.severity);
    }

    if (
      args.status &&
      args.status !== "all" &&
      !args.siteId &&
      (args.status === "open" ||
        args.status === "patched" ||
        args.status === "dismissed")
    ) {
      // Already filtered by index above
    } else if (args.status && args.status !== "all" && args.siteId) {
      vulns = vulns.filter((v) => v.status === args.status);
    }

    // Sort by severity (critical first), then by creation time
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    vulns.sort((a, b) => {
      const sa = severityOrder[a.severity] ?? 4;
      const sb = severityOrder[b.severity] ?? 4;
      if (sa !== sb) return sa - sb;
      return b._creationTime - a._creationTime;
    });

    return vulns.slice(0, args.limit ?? 500);
  },
});

export const stats = query({
  args: {},
  returns: v.object({
    total: v.number(),
    open: v.number(),
    critical: v.number(),
    high: v.number(),
    medium: v.number(),
    low: v.number(),
    patched: v.number(),
    dismissed: v.number(),
    affectedSites: v.number(),
    updateAvailable: v.number(),
  }),
  handler: async (ctx) => {
    const all = await ctx.db.query("vulnerabilities").collect();
    const openVulns = all.filter((v) => v.status === "open");
    const siteIds = new Set(openVulns.map((v) => v.siteId));
    return {
      total: all.length,
      open: openVulns.length,
      critical: openVulns.filter((v) => v.severity === "critical").length,
      high: openVulns.filter((v) => v.severity === "high").length,
      medium: openVulns.filter((v) => v.severity === "medium").length,
      low: openVulns.filter((v) => v.severity === "low").length,
      patched: all.filter((v) => v.status === "patched").length,
      dismissed: all.filter((v) => v.status === "dismissed").length,
      affectedSites: siteIds.size,
      updateAvailable: openVulns.filter((v) => v.fixedInVersion).length,
    };
  },
});

export const bySite = query({
  args: { siteId: v.id("sites") },
  returns: v.array(vulnReturnValidator),
  handler: async (ctx, args) => {
    const vulns = await ctx.db
      .query("vulnerabilities")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();
    const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
    vulns.sort(
      (a, b) =>
        (severityOrder[a.severity] ?? 4) - (severityOrder[b.severity] ?? 4),
    );
    return vulns;
  },
});

// ─── Mutations ────────────────────────────────────────────────

export const upsert = internalMutation({
  args: {
    siteId: v.id("sites"),
    pluginSlug: v.string(),
    pluginVersion: v.optional(v.string()),
    cveId: v.optional(v.string()),
    title: v.string(),
    severity: severityValidator,
    cvssScore: v.optional(v.number()),
    description: v.optional(v.string()),
    fixedInVersion: v.optional(v.string()),
    source: v.string(),
    sourceUrl: v.optional(v.string()),
  },
  returns: v.object({ id: v.id("vulnerabilities"), isNew: v.boolean() }),
  handler: async (ctx, args) => {
    // Check for existing vulnerability for this site+plugin+cve
    const existing = await ctx.db
      .query("vulnerabilities")
      .withIndex("by_site_plugin", (q) =>
        q.eq("siteId", args.siteId).eq("pluginSlug", args.pluginSlug),
      )
      .collect();

    const match = existing.find(
      (v) => v.cveId === args.cveId || (!v.cveId && !args.cveId && v.title === args.title),
    );

    if (match) {
      // Update existing
      await ctx.db.patch(match._id, {
        pluginVersion: args.pluginVersion,
        severity: args.severity,
        cvssScore: args.cvssScore,
        description: args.description,
        fixedInVersion: args.fixedInVersion,
        source: args.source,
        sourceUrl: args.sourceUrl,
      });
      return { id: match._id, isNew: false };
    }

    // Create new
    const id = await ctx.db.insert("vulnerabilities", {
      siteId: args.siteId,
      pluginSlug: args.pluginSlug,
      pluginVersion: args.pluginVersion,
      cveId: args.cveId,
      title: args.title,
      severity: args.severity,
      cvssScore: args.cvssScore,
      description: args.description,
      fixedInVersion: args.fixedInVersion,
      source: args.source,
      sourceUrl: args.sourceUrl,
      status: "open",
      firstDetectedAt: Date.now(),
      slackNotified: false,
    });
    return { id, isNew: true };
  },
});

export const updateStatus = internalMutation({
  args: {
    id: v.id("vulnerabilities"),
    status: statusValidator,
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const patch: Record<string, unknown> = { status: args.status };
    if (args.status === "patched" || args.status === "dismissed") {
      patch.resolvedAt = Date.now();
    }
    await ctx.db.patch(args.id, patch);
    return null;
  },
});

export const markNotified = internalMutation({
  args: { ids: v.array(v.id("vulnerabilities")) },
  returns: v.null(),
  handler: async (ctx, args) => {
    for (const id of args.ids) {
      await ctx.db.patch(id, { slackNotified: true });
    }
    return null;
  },
});

export const resetAllNotified = internalMutation({
  args: {},
  returns: v.object({ reset: v.number() }),
  handler: async (ctx) => {
    let count = 0;
    const vulns = await ctx.db.query("vulnerabilities").collect();
    for (const v of vulns) {
      if (v.slackNotified) {
        await ctx.db.patch(v._id, { slackNotified: false });
        count++;
      }
    }
    return { reset: count };
  },
});

export const dismiss = internalMutation({
  args: { id: v.id("vulnerabilities") },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.patch(args.id, {
      status: "dismissed",
      resolvedAt: Date.now(),
    });
    return null;
  },
});

// Public mutation for dismiss from frontend
export const dismissVuln = mutation({
  args: { id: v.id("vulnerabilities") },
  returns: v.null(),
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not authenticated");
    await ctx.db.patch(args.id, {
      status: "dismissed",
      resolvedAt: Date.now(),
    });
    return null;
  },
});

// Public mutation to reopen a dismissed/patched vulnerability
export const reopenVuln = mutation({
  args: { id: v.id("vulnerabilities") },
  returns: v.null(),
  handler: async (ctx, args) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not authenticated");
    await ctx.db.patch(args.id, {
      status: "open",
      resolvedAt: undefined,
    });
    return null;
  },
});

export const listUnnotified = internalQuery({
  args: {},
  returns: v.array(vulnReturnValidator),
  handler: async (ctx) => {
    const all = await ctx.db
      .query("vulnerabilities")
      .withIndex("by_status", (q) => q.eq("status", "open"))
      .collect();
    return all.filter((v) => !v.slackNotified);
  },
});

// Auto-patch: mark vulns as patched when the plugin is updated past the fixed version
export const autoResolvePatched = internalMutation({
  args: { siteId: v.id("sites") },
  returns: v.object({ resolved: v.number() }),
  handler: async (ctx, args) => {
    const vulns = await ctx.db
      .query("vulnerabilities")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();

    const openVulns = vulns.filter((v) => v.status === "open" && v.fixedInVersion);

    const plugins = await ctx.db
      .query("sitePlugins")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();

    let resolved = 0;
    for (const vuln of openVulns) {
      const plugin = plugins.find((p) => p.slug === vuln.pluginSlug);
      if (plugin?.version && vuln.fixedInVersion) {
        if (compareVersions(plugin.version, vuln.fixedInVersion) >= 0) {
          await ctx.db.patch(vuln._id, {
            status: "patched",
            resolvedAt: Date.now(),
          });
          resolved++;
        }
      }
    }
    return { resolved };
  },
});

// Simple semver comparison: returns 1 if a>b, -1 if a<b, 0 if equal
function compareVersions(a: string, b: string): number {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const na = pa[i] ?? 0;
    const nb = pb[i] ?? 0;
    if (na > nb) return 1;
    if (na < nb) return -1;
  }
  return 0;
}
