import { v } from "convex/values";
import { query, internalMutation, internalQuery } from "./_generated/server";

export const get = query({
  args: { key: v.string() },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    const row = await ctx.db
      .query("settings")
      .withIndex("by_key", (q) => q.eq("key", args.key))
      .unique();
    return row?.value ?? null;
  },
});

export const getInternal = internalQuery({
  args: { key: v.string() },
  returns: v.union(v.string(), v.null()),
  handler: async (ctx, args) => {
    const row = await ctx.db
      .query("settings")
      .withIndex("by_key", (q) => q.eq("key", args.key))
      .unique();
    return row?.value ?? null;
  },
});

export const setInternal = internalMutation({
  args: { key: v.string(), value: v.string() },
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("settings")
      .withIndex("by_key", (q) => q.eq("key", args.key))
      .unique();
    if (existing) {
      await ctx.db.patch(existing._id, { value: args.value });
    } else {
      await ctx.db.insert("settings", { key: args.key, value: args.value });
    }
    return null;
  },
});

export const getVulnScanProgress = query({
  args: {},
  returns: v.union(
    v.object({
      status: v.string(),
      phase: v.string(),
      total: v.number(),
      completed: v.number(),
      vulnsFound: v.optional(v.number()),
      newVulns: v.optional(v.number()),
    }),
    v.null(),
  ),
  handler: async (ctx) => {
    const row = await ctx.db
      .query("settings")
      .withIndex("by_key", (q) => q.eq("key", "vuln_scan_progress"))
      .unique();
    if (!row) return null;
    try {
      return JSON.parse(row.value);
    } catch {
      return null;
    }
  },
});

export const getSyncProgress = query({
  args: {},
  returns: v.union(
    v.object({
      status: v.string(),
      phase: v.string(),
      total: v.number(),
      completed: v.number(),
      currentSite: v.optional(v.string()),
      errors: v.number(),
      errorSites: v.optional(v.array(v.string())),
    }),
    v.null(),
  ),
  handler: async (ctx) => {
    const row = await ctx.db
      .query("settings")
      .withIndex("by_key", (q) => q.eq("key", "sync_progress"))
      .unique();
    if (!row) return null;
    try {
      return JSON.parse(row.value);
    } catch {
      return null;
    }
  },
});
