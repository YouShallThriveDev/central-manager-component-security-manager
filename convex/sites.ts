import { v } from "convex/values";
import { query, internalMutation, internalQuery, mutation } from "./_generated/server";

const gradeValidator = v.optional(
  v.union(
    v.literal("A"),
    v.literal("B"),
    v.literal("C"),
    v.literal("D"),
    v.literal("F"),
  ),
);

const siteReturnValidator = v.object({
  _id: v.id("sites"),
  _creationTime: v.number(),
  accountId: v.optional(v.id("rocketAccounts")),
  rocketSiteId: v.number(),
  domain: v.string(),
  rocketUrl: v.optional(v.string()),
  phpVersion: v.optional(v.string()),
  phpCheckedAt: v.optional(v.number()),
  wpVersion: v.optional(v.string()),
  wpUpdateAvailable: v.optional(v.boolean()),
  sslEnabled: v.optional(v.boolean()),
  lastSyncedAt: v.optional(v.number()),
  securityScore: v.optional(v.number()),
  securityGrade: gradeValidator,
  activeSecurityPlugins: v.optional(v.number()),
  totalPlugins: v.optional(v.number()),
  pluginsNeedingUpdate: v.optional(v.number()),
  hasFirewall: v.optional(v.boolean()),
  hasMalwareScanner: v.optional(v.boolean()),
  hasBackup: v.optional(v.boolean()),
  hasTwoFactor: v.optional(v.boolean()),
  hasBruteForceProtection: v.optional(v.boolean()),
  wordfenceInstalled: v.optional(v.boolean()),
  wordfenceActive: v.optional(v.boolean()),
  wordfenceVersion: v.optional(v.string()),
  lastScanAt: v.optional(v.number()),
  lastScanResult: v.optional(v.string()),
});

export const list = query({
  args: {
    search: v.optional(v.string()),
    grade: v.optional(v.string()),
    accountId: v.optional(v.id("rocketAccounts")),
  },
  returns: v.array(siteReturnValidator),
  handler: async (ctx, args) => {
    let sites;
    if (args.accountId) {
      sites = await ctx.db
        .query("sites")
        .withIndex("by_account", (q) => q.eq("accountId", args.accountId!))
        .collect();
    } else {
      sites = await ctx.db.query("sites").collect();
    }

    if (args.grade && args.grade !== "all") {
      sites = sites.filter((s) => s.securityGrade === args.grade);
    }

    if (args.search) {
      const needle = args.search.toLowerCase();
      sites = sites.filter(
        (s) =>
          s.domain.toLowerCase().includes(needle) ||
          String(s.rocketSiteId).includes(needle),
      );
    }

    sites.sort((a, b) => a.domain.localeCompare(b.domain));
    return sites;
  },
});

export const get = query({
  args: { id: v.id("sites") },
  returns: v.union(siteReturnValidator, v.null()),
  handler: async (ctx, args) => {
    return await ctx.db.get(args.id);
  },
});

export const stats = query({
  args: {},
  returns: v.object({
    total: v.number(),
    gradeA: v.number(),
    gradeB: v.number(),
    gradeC: v.number(),
    gradeD: v.number(),
    gradeF: v.number(),
    withFirewall: v.number(),
    withMalwareScanner: v.number(),
    withBackup: v.number(),
    pluginUpdatesNeeded: v.number(),
    wordfenceSites: v.number(),
  }),
  handler: async (ctx) => {
    const allSites = await ctx.db.query("sites").collect();
    return {
      total: allSites.length,
      gradeA: allSites.filter((s) => s.securityGrade === "A").length,
      gradeB: allSites.filter((s) => s.securityGrade === "B").length,
      gradeC: allSites.filter((s) => s.securityGrade === "C").length,
      gradeD: allSites.filter((s) => s.securityGrade === "D").length,
      gradeF: allSites.filter((s) => s.securityGrade === "F").length,
      withFirewall: allSites.filter((s) => s.hasFirewall).length,
      withMalwareScanner: allSites.filter((s) => s.hasMalwareScanner).length,
      withBackup: allSites.filter((s) => s.hasBackup).length,
      pluginUpdatesNeeded: allSites.filter(
        (s) => (s.pluginsNeedingUpdate ?? 0) > 0,
      ).length,
      wordfenceSites: allSites.filter((s) => s.wordfenceInstalled).length,
    };
  },
});

export const upsert = internalMutation({
  args: {
    accountId: v.optional(v.id("rocketAccounts")),
    rocketSiteId: v.number(),
    domain: v.string(),
    rocketUrl: v.optional(v.string()),
    phpVersion: v.optional(v.string()),
    wpVersion: v.optional(v.string()),
    wpUpdateAvailable: v.optional(v.boolean()),
    sslEnabled: v.optional(v.boolean()),
    securityScore: v.optional(v.number()),
    securityGrade: gradeValidator,
    activeSecurityPlugins: v.optional(v.number()),
    totalPlugins: v.optional(v.number()),
    pluginsNeedingUpdate: v.optional(v.number()),
    hasFirewall: v.optional(v.boolean()),
    hasMalwareScanner: v.optional(v.boolean()),
    hasBackup: v.optional(v.boolean()),
    hasTwoFactor: v.optional(v.boolean()),
    hasBruteForceProtection: v.optional(v.boolean()),
    wordfenceInstalled: v.optional(v.boolean()),
    wordfenceActive: v.optional(v.boolean()),
    wordfenceVersion: v.optional(v.string()),
  },
  returns: v.id("sites"),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("sites")
      .withIndex("by_rocket_site_id", (q) =>
        q.eq("rocketSiteId", args.rocketSiteId),
      )
      .unique();

    const now = Date.now();

    if (existing) {
      const patch: Record<string, unknown> = { lastSyncedAt: now };
      if (args.accountId !== undefined) patch.accountId = args.accountId;
      if (args.domain) patch.domain = args.domain;
      if (args.rocketUrl !== undefined) patch.rocketUrl = args.rocketUrl;
      if (args.phpVersion !== undefined) patch.phpVersion = args.phpVersion;
      if (args.wpVersion !== undefined) patch.wpVersion = args.wpVersion;
      if (args.wpUpdateAvailable !== undefined) patch.wpUpdateAvailable = args.wpUpdateAvailable;
      if (args.sslEnabled !== undefined) patch.sslEnabled = args.sslEnabled;
      if (args.securityScore !== undefined) patch.securityScore = args.securityScore;
      if (args.securityGrade !== undefined) patch.securityGrade = args.securityGrade;
      if (args.activeSecurityPlugins !== undefined) patch.activeSecurityPlugins = args.activeSecurityPlugins;
      if (args.totalPlugins !== undefined) patch.totalPlugins = args.totalPlugins;
      if (args.pluginsNeedingUpdate !== undefined) patch.pluginsNeedingUpdate = args.pluginsNeedingUpdate;
      if (args.hasFirewall !== undefined) patch.hasFirewall = args.hasFirewall;
      if (args.hasMalwareScanner !== undefined) patch.hasMalwareScanner = args.hasMalwareScanner;
      if (args.hasBackup !== undefined) patch.hasBackup = args.hasBackup;
      if (args.hasTwoFactor !== undefined) patch.hasTwoFactor = args.hasTwoFactor;
      if (args.hasBruteForceProtection !== undefined) patch.hasBruteForceProtection = args.hasBruteForceProtection;
      if (args.wordfenceInstalled !== undefined) patch.wordfenceInstalled = args.wordfenceInstalled;
      if (args.wordfenceActive !== undefined) patch.wordfenceActive = args.wordfenceActive;
      if (args.wordfenceVersion !== undefined) patch.wordfenceVersion = args.wordfenceVersion;

      await ctx.db.patch(existing._id, patch);
      return existing._id;
    }

    return await ctx.db.insert("sites", {
      accountId: args.accountId,
      rocketSiteId: args.rocketSiteId,
      domain: args.domain,
      rocketUrl: args.rocketUrl,
      phpVersion: args.phpVersion,
      wpVersion: args.wpVersion,
      wpUpdateAvailable: args.wpUpdateAvailable,
      sslEnabled: args.sslEnabled,
      securityScore: args.securityScore,
      securityGrade: args.securityGrade,
      activeSecurityPlugins: args.activeSecurityPlugins,
      totalPlugins: args.totalPlugins,
      pluginsNeedingUpdate: args.pluginsNeedingUpdate,
      hasFirewall: args.hasFirewall,
      hasMalwareScanner: args.hasMalwareScanner,
      hasBackup: args.hasBackup,
      hasTwoFactor: args.hasTwoFactor,
      hasBruteForceProtection: args.hasBruteForceProtection,
      wordfenceInstalled: args.wordfenceInstalled,
      wordfenceActive: args.wordfenceActive,
      wordfenceVersion: args.wordfenceVersion,
      lastSyncedAt: now,
    });
  },
});

export const listAll = internalQuery({
  args: {},
  handler: async (ctx) => {
    return await ctx.db.query("sites").collect();
  },
});

export const flagMissingSites = internalMutation({
  args: {
    validSiteIds: v.array(v.number()),
    accountId: v.optional(v.id("rocketAccounts")),
  },
  returns: v.object({ flagged: v.number(), cleared: v.number() }),
  handler: async (ctx, args) => {
    // Sites missing from Rocket.net are flagged, never deleted — removing a
    // record is a human decision.
    const validSet = new Set(args.validSiteIds);

    let allSites;
    if (args.accountId) {
      allSites = await ctx.db
        .query("sites")
        .withIndex("by_account", (q) => q.eq("accountId", args.accountId!))
        .collect();
    } else {
      allSites = await ctx.db.query("sites").collect();
    }

    let flagged = 0;
    let cleared = 0;
    for (const site of allSites) {
      if (!validSet.has(site.rocketSiteId)) {
        if (site.rocketStatus !== "missing") {
          await ctx.db.patch(site._id, {
            rocketStatus: "missing",
            rocketMissingSince: site.rocketMissingSince ?? Date.now(),
          });
        }
        flagged++;
      } else if (site.rocketStatus === "missing") {
        await ctx.db.patch(site._id, { rocketStatus: "ok", rocketMissingSince: undefined });
        cleared++;
      }
    }

    return { flagged, cleared };
  },
});


/**
 * Human-initiated removal of a site record. Sync never deletes records — a
 * site missing from Rocket.net is flagged and stays visible until someone
 * explicitly removes it here.
 */
export const removeSite = mutation({
  args: { siteId: v.id("sites") },
  returns: v.null(),
  handler: async (ctx, { siteId }) => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not authenticated");

    const plugins = await ctx.db
      .query("sitePlugins")
      .withIndex("by_site", (q) => q.eq("siteId", siteId))
      .collect();
    for (const p of plugins) await ctx.db.delete(p._id);

    const muPlugins = await ctx.db
      .query("siteMuPlugins")
      .withIndex("by_site", (q) => q.eq("siteId", siteId))
      .collect();
    for (const m of muPlugins) await ctx.db.delete(m._id);
    await ctx.db.delete(siteId);
    return null;
  },
});
