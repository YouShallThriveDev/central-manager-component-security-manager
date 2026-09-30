/**
 * Bulk "fix on staging": for selected production sites, apply v1 fixes to
 * each site's Rocket.net STAGING copy only. Pushing staging → live is out of
 * scope; nothing here writes to a production site (see stagingGuard.ts).
 *
 * Existing plugin/vuln scans are keyed to production site records, so a
 * staging rescan isn't possible yet — before/after plugin versions are
 * re-read from staging and stored on each action instead.
 */
import { getAuthUserId } from "@convex-dev/auth/server";
import { type Infer, v } from "convex/values";
import { internal } from "./_generated/api";
import type { Id } from "./_generated/dataModel";
import {
  internalAction,
  internalMutation,
  internalQuery,
  mutation,
  type QueryCtx,
  query,
} from "./_generated/server";
import { stagingFixAction, stagingFixStatus } from "./schema";
import {
  assertStagingTarget,
  type StagingParent,
  type StagingTarget,
} from "./stagingGuard";
import { compareVersions } from "./vulnScan";

const ROCKET_API_BASE = "https://api.rocket.net/v1";
const CONCURRENCY = 3;
const WORDFENCE = "wordfence";
const VERIFY_ATTEMPTS = 4;
const VERIFY_DELAY_MS = 5000;
const VERIFYING = "Requested, verifying on staging";

type FixAction = Infer<typeof stagingFixAction>;

// ─── Dry-run plan ────────────────────────────────────────────

async function buildPlan(ctx: QueryCtx, siteId: Id<"sites">) {
  const site = await ctx.db.get(siteId);
  if (!site) return null;

  const vulns = await ctx.db
    .query("vulnerabilities")
    .withIndex("by_site", q => q.eq("siteId", siteId))
    .collect();
  const bySlug = new Map<string, FixAction>();
  for (const x of vulns) {
    if (x.status !== "open") continue;
    const a: FixAction = bySlug.get(x.pluginSlug) ?? {
      kind: "update_plugin",
      slug: x.pluginSlug,
      fromVersion: x.pluginVersion,
      status: "pending",
    };
    if (
      x.fixedInVersion &&
      (!a.fixedIn || compareVersions(x.fixedInVersion, a.fixedIn) > 0)
    ) {
      a.fixedIn = x.fixedInVersion;
    }
    bySlug.set(x.pluginSlug, a);
  }
  const actions = [...bySlug.values()];
  if (site.wordfenceInstalled && !site.wordfenceActive) {
    actions.push({
      kind: "activate_wordfence",
      slug: WORDFENCE,
      name: "Wordfence",
      status: "pending",
    });
  }

  const skipReason = !site.stagingSiteId
    ? "No staging copy on Rocket.net"
    : site.rocketStatus === "missing"
      ? "Site is missing from Rocket.net"
      : actions.length === 0
        ? "Nothing to fix"
        : undefined;

  return {
    siteId,
    domain: site.domain,
    stagingSiteId: site.stagingSiteId,
    skipReason,
    actions,
  };
}

const planValidator = v.object({
  siteId: v.id("sites"),
  domain: v.string(),
  stagingSiteId: v.optional(v.number()),
  skipReason: v.optional(v.string()),
  actions: v.array(stagingFixAction),
});

export const plan = query({
  args: { siteIds: v.array(v.id("sites")) },
  returns: v.array(planValidator),
  handler: async (ctx, { siteIds }) => {
    const plans = await Promise.all(
      [...new Set(siteIds)].map(id => buildPlan(ctx, id)),
    );
    return plans.filter(p => p !== null);
  },
});

// ─── Job queue ───────────────────────────────────────────────

export const start = mutation({
  args: { siteIds: v.array(v.id("sites")) },
  returns: v.id("stagingFixJobs"),
  handler: async (ctx, { siteIds }) => {
    const userId = await getAuthUserId(ctx);
    if (!userId) throw new Error("Not authenticated");

    const plans = (
      await Promise.all([...new Set(siteIds)].map(id => buildPlan(ctx, id)))
    ).filter(p => p !== null);
    const jobId = await ctx.db.insert("stagingFixJobs", {
      status: "running",
      total: plans.length,
      startedBy: userId,
    });

    let queued = 0;
    for (const p of plans) {
      await ctx.db.insert("stagingFixItems", {
        jobId,
        siteId: p.siteId,
        domain: p.domain,
        stagingSiteId: p.stagingSiteId,
        status: p.skipReason ? "skipped" : "queued",
        error: p.skipReason,
        actions: p.actions,
      });
      if (!p.skipReason) queued++;
    }

    if (queued === 0) {
      await ctx.db.patch(jobId, { status: "done", finishedAt: Date.now() });
    }
    for (let i = 0; i < Math.min(CONCURRENCY, queued); i++) {
      await ctx.scheduler.runAfter(0, internal.stagingFix.worker, { jobId });
    }
    return jobId;
  },
});

export const job = query({
  args: { jobId: v.id("stagingFixJobs") },
  returns: v.union(
    v.null(),
    v.object({
      _id: v.id("stagingFixJobs"),
      _creationTime: v.number(),
      status: v.union(v.literal("running"), v.literal("done")),
      total: v.number(),
      finishedAt: v.optional(v.number()),
      items: v.array(
        v.object({
          _id: v.id("stagingFixItems"),
          domain: v.string(),
          stagingSiteId: v.optional(v.number()),
          status: stagingFixStatus,
          error: v.optional(v.string()),
          actions: v.array(stagingFixAction),
        }),
      ),
    }),
  ),
  handler: async (ctx, { jobId }) => {
    const j = await ctx.db.get(jobId);
    if (!j) return null;
    const items = await ctx.db
      .query("stagingFixItems")
      .withIndex("by_job", q => q.eq("jobId", jobId))
      .collect();
    return {
      _id: j._id,
      _creationTime: j._creationTime,
      status: j.status,
      total: j.total,
      finishedAt: j.finishedAt,
      items: items.map(i => ({
        _id: i._id,
        domain: i.domain,
        stagingSiteId: i.stagingSiteId,
        status: i.status,
        error: i.error,
        actions: i.actions,
      })),
    };
  },
});

export const latestJobId = query({
  args: {},
  returns: v.union(v.id("stagingFixJobs"), v.null()),
  handler: async ctx => {
    const j = await ctx.db.query("stagingFixJobs").order("desc").first();
    return j?._id ?? null;
  },
});

export const claimNext = internalMutation({
  args: { jobId: v.id("stagingFixJobs") },
  handler: async (ctx, { jobId }) => {
    const item = await ctx.db
      .query("stagingFixItems")
      .withIndex("by_job_and_status", q =>
        q.eq("jobId", jobId).eq("status", "queued"),
      )
      .first();
    if (!item) return null;
    await ctx.db.patch(item._id, { status: "running", startedAt: Date.now() });
    return item;
  },
});

export const saveItem = internalMutation({
  args: {
    itemId: v.id("stagingFixItems"),
    actions: v.array(stagingFixAction),
    status: v.optional(stagingFixStatus),
    error: v.optional(v.string()),
  },
  returns: v.null(),
  handler: async (ctx, { itemId, actions, status, error }) => {
    const item = await ctx.db.get(itemId);
    if (!item) return null;
    if (!status) {
      await ctx.db.patch(itemId, { actions });
      return null;
    }
    await ctx.db.patch(itemId, {
      actions,
      status,
      error,
      finishedAt: Date.now(),
    });

    const summary = actions
      .map(a => `${a.slug}: ${a.status}${a.note ? ` (${a.note})` : ""}`)
      .join("; ");
    await ctx.db.insert("actionLogs", {
      siteId: item.siteId,
      action: "staging_fix",
      details: `Staging ${item.stagingSiteId} of ${item.domain}: ${error ?? summary}`,
      status: status === "done" ? "success" : "error",
    });

    const items = await ctx.db
      .query("stagingFixItems")
      .withIndex("by_job", q => q.eq("jobId", item.jobId))
      .collect();
    if (!items.some(i => i.status === "queued" || i.status === "running")) {
      await ctx.db.patch(item.jobId, {
        status: "done",
        finishedAt: Date.now(),
      });
    }
    return null;
  },
});

export const siteForFix = internalQuery({
  args: { siteId: v.id("sites") },
  handler: async (ctx, { siteId }) => {
    const site = await ctx.db.get(siteId);
    if (!site) return null;
    const account = site.accountId ? await ctx.db.get(site.accountId) : null;
    const apiToken =
      account?.apiToken ??
      (await ctx.db.query("rocketAccounts").collect()).find(a => a.apiToken)
        ?.apiToken;
    return {
      rocketSiteId: site.rocketSiteId,
      stagingSiteId: site.stagingSiteId,
      apiToken,
    };
  },
});

export const worker = internalAction({
  args: { jobId: v.id("stagingFixJobs") },
  returns: v.null(),
  handler: async (ctx, { jobId }): Promise<null> => {
    const item = await ctx.runMutation(internal.stagingFix.claimNext, {
      jobId,
    });
    if (!item) return null;

    const actions: FixAction[] = item.actions.map(a => ({ ...a }));
    const save = () =>
      ctx.runMutation(internal.stagingFix.saveItem, {
        itemId: item._id,
        actions,
      });
    let error: string | undefined;
    try {
      const site = await ctx.runQuery(internal.stagingFix.siteForFix, {
        siteId: item.siteId,
      });
      if (!site?.apiToken)
        throw new Error("No Rocket.net API token for this site's account");
      await fixSite(site.apiToken, site, actions, save);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
      for (const a of actions) {
        if (a.status !== "pending") continue;
        Object.assign(
          a,
          a.note === VERIFYING
            ? {
                status: "failed",
                note: "Sent, but could not verify on staging",
              }
            : { status: "skipped", note: "Not run" },
        );
      }
    }

    const failed =
      error !== undefined || actions.some(a => a.status === "failed");
    await ctx.runMutation(internal.stagingFix.saveItem, {
      itemId: item._id,
      actions,
      status: failed ? "failed" : "done",
      error,
    });
    await ctx.scheduler.runAfter(0, internal.stagingFix.worker, { jobId });
    return null;
  },
});

// ─── Per-site run ────────────────────────────────────────────

async function fixSite(
  token: string,
  parent: StagingParent,
  actions: FixAction[],
  save: () => Promise<unknown>,
) {
  if (!parent.stagingSiteId) throw new Error("No staging copy on record");
  const detail = await rocketGet(token, `/sites/${parent.stagingSiteId}`);
  const target: StagingTarget = {
    id: detail.id,
    domain: detail.domain,
    production: detail.production,
  };
  assertStagingTarget(target, parent);

  const before = await stagingPlugins(token, parent.stagingSiteId);
  const requested: FixAction[] = [];
  for (const a of actions) {
    const p = before.get(a.slug);
    if (!p) {
      Object.assign(a, { status: "skipped", note: "Not installed on staging" });
      continue;
    }
    a.fromVersion = p.version || a.fromVersion;
    a.name = p.title || a.name;
    try {
      if (a.kind === "update_plugin") {
        if (!p.update || p.update === "none") {
          Object.assign(a, {
            status: "skipped",
            note: `No update available on staging (v${p.version})`,
          });
          continue;
        }
        await updateStagingPlugin(token, target, parent, a.slug);
      } else {
        if (p.status === "active") {
          Object.assign(a, {
            status: "skipped",
            note: "Already active on staging",
          });
          continue;
        }
        await activateStagingPlugin(token, target, parent, a.slug);
      }
      a.note = VERIFYING;
      requested.push(a);
    } catch (e) {
      Object.assign(a, {
        status: "failed",
        note: e instanceof Error ? e.message : String(e),
      });
    }
    await save();
  }

  // Re-read staging until each requested change shows up
  const applied = (a: FixAction, p?: RocketPlugin) =>
    !!p &&
    (a.kind === "update_plugin"
      ? p.version !== a.fromVersion
      : p.status === "active");
  for (let i = 0; i < VERIFY_ATTEMPTS && requested.length > 0; i++) {
    await new Promise(r => setTimeout(r, VERIFY_DELAY_MS));
    const after = await stagingPlugins(token, parent.stagingSiteId);
    for (const a of requested) a.toVersion = after.get(a.slug)?.version;
    if (
      requested.every(a => applied(a, after.get(a.slug))) ||
      i === VERIFY_ATTEMPTS - 1
    ) {
      for (const a of requested) {
        const p = after.get(a.slug);
        if (!applied(a, p)) {
          a.status = "failed";
          a.note =
            a.kind === "update_plugin"
              ? `Rocket.net accepted the update but staging still reports v${p?.version ?? "?"}`
              : "Rocket.net accepted the request but the plugin is still inactive";
        } else {
          a.status = "done";
          a.note = undefined;
          if (
            a.fixedIn &&
            a.toVersion &&
            compareVersions(a.toVersion, a.fixedIn) < 0
          ) {
            a.note = `Updated, but still below the fixed version ${a.fixedIn}`;
          }
        }
      }
      break;
    }
  }
}

// ─── Rocket.net API ──────────────────────────────────────────

type RocketPlugin = {
  name: string;
  status: string;
  version: string;
  update?: string;
  title?: string;
};

// Retry once on 401 — Rocket.net occasionally returns a transient 401.
async function rocketFetch(url: string, init: RequestInit): Promise<Response> {
  const resp = await fetch(url, init);
  if (resp.status !== 401) return resp;
  await new Promise(r => setTimeout(r, 1500));
  return await fetch(url, init);
}

const rocketHeaders = (token: string) => ({
  Authorization: `Bearer ${token}`,
  Accept: "application/json",
  "User-Agent": "Mozilla/5.0 (compatible; SecurityManager/1.0)",
});

async function rocketGet(
  token: string,
  path: string,
): Promise<Record<string, unknown>> {
  const resp = await rocketFetch(`${ROCKET_API_BASE}${path}`, {
    headers: rocketHeaders(token),
  });
  if (!resp.ok)
    throw new Error(`Rocket.net GET ${path} failed (${resp.status})`);
  const body = (await resp.json()) as { result?: Record<string, unknown> };
  return body.result ?? {};
}

async function stagingPlugins(
  token: string,
  stagingSiteId: number,
): Promise<Map<string, RocketPlugin>> {
  const resp = await rocketFetch(
    `${ROCKET_API_BASE}/sites/${stagingSiteId}/plugins`,
    {
      headers: rocketHeaders(token),
    },
  );
  if (!resp.ok)
    throw new Error(
      `Rocket.net GET /sites/${stagingSiteId}/plugins failed (${resp.status})`,
    );
  const body = (await resp.json()) as { result?: RocketPlugin[] };
  return new Map((body.result ?? []).map(p => [p.name, p]));
}

/** The only code path that sends a write request to Rocket.net. */
async function stagingWrite(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  method: "PUT" | "PATCH",
  subpath: string,
  body: Record<string, unknown>,
) {
  const id = assertStagingTarget(target, parent);
  const resp = await rocketFetch(`${ROCKET_API_BASE}/sites/${id}${subpath}`, {
    method,
    headers: { ...rocketHeaders(token), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!resp.ok) {
    const text = (await resp.text()).slice(0, 300);
    throw new Error(
      `Rocket.net ${method} ${subpath} failed (${resp.status}): ${text}`,
    );
  }
}

// Endpoint + method confirmed from the site's own API links
// (rel "update_site_plugin": PUT /sites/{id}/plugins).
// TODO(unconfirmed): request body shape — no Rocket.net API reference was
// reachable. The verify step re-reads staging, so a no-op shows as failed.
function updateStagingPlugin(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  slug: string,
) {
  return stagingWrite(token, target, parent, "PUT", "/plugins", {
    plugins: slug,
  });
}

// Endpoint + method confirmed from the site's own API links
// (rel "toggle_plugin_status": PATCH /sites/{id}/plugins).
// TODO(unconfirmed): request body shape, as above.
function activateStagingPlugin(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  slug: string,
) {
  return stagingWrite(token, target, parent, "PATCH", "/plugins", {
    plugins: slug,
    action: "activate",
  });
}
