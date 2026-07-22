import { v } from "convex/values";
import { query, internalMutation } from "./_generated/server";

export const listBySite = query({
  args: { siteId: v.id("sites") },
  returns: v.array(
    v.object({
      _id: v.id("siteMuPlugins"),
      _creationTime: v.number(),
      siteId: v.id("sites"),
      filename: v.string(),
      present: v.boolean(),
      isSecurityRelated: v.boolean(),
    }),
  ),
  handler: async (ctx, args) => {
    return await ctx.db
      .query("siteMuPlugins")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();
  },
});

export const batchUpsert = internalMutation({
  args: {
    siteId: v.id("sites"),
    muPlugins: v.array(
      v.object({
        filename: v.string(),
        present: v.boolean(),
        isSecurityRelated: v.boolean(),
      }),
    ),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const existing = await ctx.db
      .query("siteMuPlugins")
      .withIndex("by_site", (q) => q.eq("siteId", args.siteId))
      .collect();
    for (const m of existing) {
      await ctx.db.delete(m._id);
    }

    for (const muPlugin of args.muPlugins) {
      await ctx.db.insert("siteMuPlugins", {
        siteId: args.siteId,
        ...muPlugin,
      });
    }
    return null;
  },
});
