import { v } from "convex/values";
import { query, internalMutation } from "./_generated/server";

export const list = query({
  args: {
    siteId: v.optional(v.id("sites")),
    limit: v.optional(v.number()),
  },
  returns: v.array(
    v.object({
      _id: v.id("actionLogs"),
      _creationTime: v.number(),
      siteId: v.optional(v.id("sites")),
      action: v.string(),
      details: v.string(),
      status: v.union(
        v.literal("success"),
        v.literal("error"),
        v.literal("info"),
      ),
    }),
  ),
  handler: async (ctx, args) => {
    let q;
    if (args.siteId) {
      q = ctx.db
        .query("actionLogs")
        .withIndex("by_site", (q) => q.eq("siteId", args.siteId!));
    } else {
      q = ctx.db.query("actionLogs");
    }
    const logs = await q.order("desc").collect();
    return logs.slice(0, args.limit ?? 100);
  },
});

export const add = internalMutation({
  args: {
    siteId: v.optional(v.id("sites")),
    action: v.string(),
    details: v.string(),
    status: v.union(
      v.literal("success"),
      v.literal("error"),
      v.literal("info"),
    ),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.insert("actionLogs", {
      siteId: args.siteId,
      action: args.action,
      details: args.details,
      status: args.status,
    });
    return null;
  },
});
