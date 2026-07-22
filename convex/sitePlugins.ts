import { v } from "convex/values";
import { query, internalMutation, internalQuery } from "./_generated/server";

const categoryValidator = v.optional(
  v.union(
    v.literal("firewall"),
    v.literal("malware"),
    v.literal("brute-force"),
    v.literal("two-factor"),
    v.literal("backup"),
    v.literal("general-security"),
    v.literal("monitoring"),
  ),
);

export const listBySite = query({
  args: { siteId: v.id("sites") },
  returns: v.array(
    v.object({
      _id: v.id("sitePlugins"),
      _creationTime: v.number(),
      siteId: v.id("sites"),
      slug: v.string(),
      displayName: v.optional(v.string()),
      status: v.union(
        v.literal("active"),
        v.literal("inactive"),
        v.literal("must-use"),
      ),
      version: v.optional(v.string()),
      updateAvailable: v.optional(v.boolean()),
      isSecurityPlugin: v.boolean(),
      securityCategory: categoryValidator,
    }),
  ),
  handler: async (ctx, args) => {
    return await ctx.db
      .query("sitePlugins")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();
  },
});

export const listAllBySite = internalQuery({
  args: { siteId: v.id("sites") },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("sitePlugins")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();
  },
});

export const batchUpsert = internalMutation({
  args: {
    siteId: v.id("sites"),
    plugins: v.array(
      v.object({
        slug: v.string(),
        displayName: v.optional(v.string()),
        status: v.union(
          v.literal("active"),
          v.literal("inactive"),
          v.literal("must-use"),
        ),
        version: v.optional(v.string()),
        updateAvailable: v.optional(v.boolean()),
        isSecurityPlugin: v.boolean(),
        securityCategory: categoryValidator,
      }),
    ),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    // Delete existing plugins for this site
    const existing = await ctx.db
      .query("sitePlugins")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();
    for (const p of existing) {
      await ctx.db.delete(p._id);
    }

    // Insert new
    for (const plugin of args.plugins) {
      await ctx.db.insert("sitePlugins", {
        siteId: args.siteId,
        ...plugin,
      });
    }
    return null;
  },
});
