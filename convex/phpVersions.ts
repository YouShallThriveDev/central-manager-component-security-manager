/**
 * PHP version sync.
 *
 * Rocket.net's /sites list does NOT include the PHP version — it is only
 * available per site via GET /sites/{id}/settings -> current_php_version.
 * So this runs as its own batched sweep: one settings call per site,
 * BATCH_SIZE sites per action, scheduling the next batch until done.
 */
import { v } from "convex/values";
import { action, internalAction, internalMutation, internalQuery, query } from "./_generated/server";
import { internal } from "./_generated/api";

const ROCKET_API_BASE = "https://api.rocket.net/v1";
const BATCH_SIZE = 20;
const CONCURRENCY = 5;

async function fetchPhpVersion(token: string, rocketSiteId: number): Promise<string | undefined> {
  const resp = await fetch(`${ROCKET_API_BASE}/sites/${rocketSiteId}/settings`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 (compatible; SecurityManager/1.0)",
    },
  });

  if (!resp.ok) {
    if (resp.status === 401) {
      throw new Error("Rocket.net API token is invalid or expired. Go to Servers to update it.");
    }
    throw new Error(`Rocket.net API error (${resp.status}) fetching settings for site ${rocketSiteId}`);
  }

  const body = (await resp.json()) as { result?: { current_php_version?: string } };
  const version = body.result?.current_php_version;
  return version ? String(version) : undefined;
}

export const listForPhpSync = internalQuery({
  args: {},
  handler: async (ctx) => {
    const sites = await ctx.db.query("sites").collect();
    return sites.map((s) => ({ _id: s._id, rocketSiteId: s.rocketSiteId, domain: s.domain }));
  },
});

export const setPhpVersion = internalMutation({
  args: {
    siteId: v.id("sites"),
    phpVersion: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.patch(args.siteId, {
      phpVersion: args.phpVersion,
      phpCheckedAt: Date.now(),
    });
    return null;
  },
});

export const syncBatch = internalAction({
  args: { offset: v.number() },
  returns: v.object({
    checked: v.number(),
    errors: v.number(),
    hasMore: v.boolean(),
  }),
  handler: async (ctx, { offset }): Promise<{ checked: number; errors: number; hasMore: boolean }> => {
    const accounts: Array<{ apiToken?: string }> = await ctx.runQuery(
      internal.rocketAccounts.listAll,
      {},
    );
    const account = accounts.find((a) => a.apiToken);
    if (!account?.apiToken) return { checked: 0, errors: 0, hasMore: false };

    const sites: Array<{ _id: string; rocketSiteId: number; domain: string }> =
      await ctx.runQuery(internal.phpVersions.listForPhpSync, {});
    const batch = sites.slice(offset, offset + BATCH_SIZE);
    if (batch.length === 0) return { checked: 0, errors: 0, hasMore: false };

    let checked = 0;
    let errors = 0;

    for (let i = 0; i < batch.length; i += CONCURRENCY) {
      const slice = batch.slice(i, i + CONCURRENCY);
      await Promise.all(
        slice.map(async (site) => {
          try {
            const phpVersion = await fetchPhpVersion(account.apiToken!, site.rocketSiteId);
            await ctx.runMutation(internal.phpVersions.setPhpVersion, {
              siteId: site._id as any,
              phpVersion,
            });
            checked++;
          } catch (e) {
            errors++;
            console.error(`PHP version sync failed for ${site.domain}:`, e instanceof Error ? e.message : String(e));
          }
        }),
      );
    }

    const hasMore = offset + BATCH_SIZE < sites.length;
    if (hasMore) {
      await ctx.scheduler.runAfter(500, internal.phpVersions.syncBatch, {
        offset: offset + BATCH_SIZE,
      });
    } else {
      await ctx.runMutation(internal.actionLogs.add, {
        action: "php_version_sync",
        details: `PHP version sweep complete: ${offset + checked} sites checked`,
        status: errors > 0 ? "error" : "success",
      });
    }

    return { checked, errors, hasMore };
  },
});

/** Kick off a full PHP version sweep across every known site. */
export const syncAll = action({
  args: {},
  returns: v.object({ scheduled: v.boolean(), sites: v.number() }),
  handler: async (ctx): Promise<{ scheduled: boolean; sites: number }> => {
    const identity = await ctx.auth.getUserIdentity();
    if (!identity) throw new Error("Not authenticated");

    const sites: Array<unknown> = await ctx.runQuery(internal.phpVersions.listForPhpSync, {});
    await ctx.scheduler.runAfter(0, internal.phpVersions.syncBatch, { offset: 0 });
    return { scheduled: true, sites: sites.length };
  },
});

/** Fleet-wide PHP version breakdown for the dashboard summary. */
export const summary = query({
  args: {},
  returns: v.object({
    total: v.number(),
    known: v.number(),
    unknown: v.number(),
    critical: v.number(),
    warning: v.number(),
    ok: v.number(),
    lastCheckedAt: v.optional(v.number()),
    byVersion: v.array(v.object({ version: v.string(), count: v.number() })),
  }),
  handler: async (ctx) => {
    const sites = await ctx.db.query("sites").collect();
    const counts = new Map<string, number>();
    let known = 0;
    let critical = 0;
    let warning = 0;
    let ok = 0;
    let lastCheckedAt: number | undefined;

    for (const s of sites) {
      if (s.phpCheckedAt && (!lastCheckedAt || s.phpCheckedAt > lastCheckedAt)) {
        lastCheckedAt = s.phpCheckedAt;
      }
      if (!s.phpVersion) continue;
      known++;
      counts.set(s.phpVersion, (counts.get(s.phpVersion) ?? 0) + 1);
      const num = parseFloat(s.phpVersion);
      if (Number.isNaN(num)) continue;
      if (num < 8.0) critical++;
      else if (num < 8.1) warning++;
      else ok++;
    }

    const byVersion = Array.from(counts.entries())
      .map(([version, count]) => ({ version, count }))
      .sort((a, b) => parseFloat(b.version) - parseFloat(a.version));

    return {
      total: sites.length,
      known,
      unknown: sites.length - known,
      critical,
      warning,
      ok,
      lastCheckedAt,
      byVersion,
    };
  },
});
