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

// Retry once on 401 — Rocket.net occasionally returns a transient 401 mid-sync.
async function rocketFetch(url: string, init: RequestInit): Promise<Response> {
  const resp = await fetch(url, init);
  if (resp.status !== 401) return resp;
  await new Promise((r) => setTimeout(r, 1500));
  return await fetch(url, init);
}

export type RocketStatus = "ok" | "missing" | "auth_error";

/**
 * Probes a site's settings endpoint and classifies the outcome.
 * 404 = the site no longer exists on Rocket.net (flagged, never deleted).
 * 401/403 = a token problem, never treated as a missing site.
 */
async function probeSite(
  token: string,
  rocketSiteId: number,
): Promise<{ status: RocketStatus; version?: string }> {
  if (!rocketSiteId || rocketSiteId <= 0) return { status: "missing" };
  const resp = await rocketFetch(`${ROCKET_API_BASE}/sites/${rocketSiteId}/settings`, {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 (compatible; SecurityManager/1.0)",
    },
  });

  if (!resp.ok) {
    if (resp.status === 404) return { status: "missing" };
    if (resp.status === 401 || resp.status === 403) return { status: "auth_error" };
    throw new Error(
      `Sync error (${resp.status} from Rocket.net) fetching settings for site ${rocketSiteId}. Check the sync logs for details.`,
    );
  }

  const body = (await resp.json()) as { result?: { current_php_version?: string } };
  const version = body.result?.current_php_version;
  return { status: "ok", version: version ? String(version) : undefined };
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
    rocketStatus: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const site = await ctx.db.get(args.siteId);
    const patch: Record<string, unknown> = { phpCheckedAt: Date.now() };

    if (args.rocketStatus === "missing" || args.rocketStatus === "auth_error") {
      // Unreadable on Rocket.net — keep the last known PHP version and flag
      // the record. Site records are never deleted automatically.
      patch.rocketStatus = args.rocketStatus;
      if (args.rocketStatus === "missing") {
        patch.rocketMissingSince = site?.rocketMissingSince ?? Date.now();
      }
    } else {
      patch.phpVersion = args.phpVersion;
      patch.rocketStatus = "ok";
      patch.rocketMissingSince = undefined;
    }

    await ctx.db.patch(args.siteId, patch);
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
    // Rocket.net JWTs expire ~weekly; refresh credentials from Server Management
    // before the first batch so a stale token doesn't 401 the whole sweep.
    if (offset === 0) {
      try {
        await ctx.runAction(internal.credentialSync.pullFromServerManagement, {});
      } catch (e) {
        console.warn("Credential sync warning:", e instanceof Error ? e.message : String(e));
      }
    }

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
            const probe = await probeSite(account.apiToken!, site.rocketSiteId);
            await ctx.runMutation(internal.phpVersions.setPhpVersion, {
              siteId: site._id as any,
              phpVersion: probe.version,
              rocketStatus: probe.status,
            });
            if (probe.status === "ok") checked++;
            else {
              errors++;
              console.error(`PHP version sync: ${site.domain} is ${probe.status} on Rocket.net`);
            }
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
