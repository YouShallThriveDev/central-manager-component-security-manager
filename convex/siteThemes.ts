import { v } from "convex/values";
import { query, internalMutation, internalQuery } from "./_generated/server";

const themeFields = {
  slug: v.string(),
  displayName: v.optional(v.string()),
  status: v.string(),
  version: v.optional(v.string()),
  updateAvailable: v.optional(v.boolean()),
  updateVersion: v.optional(v.string()),
};

export const listBySite = query({
  args: { siteId: v.id("sites") },
  returns: v.array(
    v.object({
      _id: v.id("siteThemes"),
      _creationTime: v.number(),
      siteId: v.id("sites"),
      ...themeFields,
    }),
  ),
  handler: async (ctx, args) => {
    return await ctx.db
      .query("siteThemes")
      .withIndex("by_site", q => q.eq("siteId", args.siteId))
      .collect();
  },
});

export const listAllBySite = internalQuery({
  args: { siteId: v.id("sites") },
  handler: async (ctx, args) => {
    return await ctx.db
      .query("siteThemes")
      .withIndex("by_site", q => q.eq("siteId", args.siteId))
      .collect();
  },
});

/** Replace a site's stored themes with the latest list from Rocket.net. */
export const batchUpsert = internalMutation({
  args: {
    siteId: v.id("sites"),
    themes: v.array(v.object(themeFields)),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("siteThemes")
      .withIndex("by_site", q => q.eq("siteId", args.siteId))
      .collect();
    for (const t of existing) {
      await ctx.db.delete(t._id);
    }
    for (const theme of args.themes) {
      await ctx.db.insert("siteThemes", { siteId: args.siteId, ...theme });
    }
    return null;
  },
});
