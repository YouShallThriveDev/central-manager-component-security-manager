/**
 * Bulk "fix on staging": for selected production sites, apply v1 fixes to
 * each site's Rocket.net STAGING copy only. Pushing staging → live is out of
 * scope; nothing here writes to a production site (see stagingGuard.ts).
 *
 * Existing plugin/vuln scans are keyed to production site records, so a
 * staging rescan isn't possible yet — before/after plugin versions are
 * re-read from staging and stored on each action instead.
 *
 * When a plugin can't be updated, diagnose() works out why (already fixed,
 * no fix released, the update error itself, closed on wordpress.org,
 * bundled with the theme, vendor license state) using read-only WP-CLI on
 * staging and the wordpress.org plugins API, and stores reason/detail.
 *
 * Themes with open vulnerabilities get an update_theme action, run the same
 * way through PUT /themes. A plugin found to be bundled with a theme that has
 * an update on staging adds (or joins) an update_theme for that theme.
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
// Re-read staging after these waits (ms), ~2 min in total. Rocket.net's PUT
// /plugins runs the update synchronously (activity log shows each update
// finishing before the next request; /tasks stays empty), so the first
// re-read usually confirms it — the rest is slack for slow sites.
const VERIFY_DELAYS_MS = [2, 3, 5, 8, 12, 15, 20, 25, 30].map(s => s * 1000);
const VERIFYING = "Requested, verifying on staging";
// Rocket.net's "nothing to update" notes
const ALREADY_RE = /already updated|up to date|no update/i;

type FixAction = Infer<typeof stagingFixAction>;

// ─── Dry-run plan ────────────────────────────────────────────

async function buildPlan(ctx: QueryCtx, siteId: Id<"sites">) {
  const site = await ctx.db.get(siteId);
  if (!site) return null;

  const vulns = await ctx.db
    .query("vulnerabilities")
    .withIndex("by_site", q => q.eq("siteId", siteId))
    .collect();
  const themeNames = new Map(
    (
      await ctx.db
        .query("siteThemes")
        .withIndex("by_site", q => q.eq("siteId", siteId))
        .collect()
    ).map(t => [t.slug, t.displayName]),
  );
  const byKey = new Map<string, FixAction>();
  for (const x of vulns) {
    if (x.status !== "open") continue;
    const theme = x.componentType === "theme";
    const key = `${theme ? "theme" : "plugin"}:${x.pluginSlug}`;
    const a: FixAction = byKey.get(key) ?? {
      kind: theme ? "update_theme" : "update_plugin",
      slug: x.pluginSlug,
      name: theme ? themeNames.get(x.pluginSlug) : undefined,
      fromVersion: x.pluginVersion,
      prodVersion: x.pluginVersion,
      status: "pending",
    };
    if (
      x.fixedInVersion &&
      (!a.fixedIn || compareVersions(x.fixedInVersion, a.fixedIn) > 0)
    ) {
      a.fixedIn = x.fixedInVersion;
    }
    byKey.set(key, a);
  }
  const all = [...byKey.values()];
  // Theme updates run after plugins (and are listed after them)
  const actions = all.filter(a => a.kind !== "update_theme");
  if (site.wordfenceInstalled && !site.wordfenceActive) {
    actions.push({
      kind: "activate_wordfence",
      slug: WORDFENCE,
      name: "Wordfence",
      status: "pending",
    });
  }
  actions.push(...all.filter(a => a.kind === "update_theme"));

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
      .map(a => {
        const why = a.reason ?? a.note;
        const what = a.kind === "update_theme" ? `theme ${a.slug}` : a.slug;
        return `${what}: ${a.status}${why ? ` (${why})` : ""}`;
      })
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

type Source = "plugins" | "themes";
const sourceOf = (a: FixAction): Source =>
  a.kind === "update_theme" ? "themes" : "plugins";
const isUpdate = (a: FixAction) =>
  a.kind === "update_plugin" || a.kind === "update_theme";

type RunCtx = {
  token: string;
  target: StagingTarget;
  parent: StagingParent;
  probe: Probe;
  actions: FixAction[];
  /** Staging's list as read at the start of the run (memoized). */
  staging: (s: Source) => Promise<Map<string, RocketItem>>;
  /** Production's list, read-only (memoized; empty if it can't be read). */
  prod: (s: Source) => Promise<Map<string, RocketItem>>;
  /** A plugin turned out to be bundled with `theme`: plan (or extend) an
   *  update_theme for it. True when a theme update is in the plan. */
  planThemeFor: (theme: WpCliTheme, plugin: FixAction) => Promise<boolean>;
};

async function fixSite(
  token: string,
  parent: StagingParent,
  actions: FixAction[],
  save: () => Promise<unknown>,
) {
  if (!parent.stagingSiteId) throw new Error("No staging copy on record");
  const stagingId = parent.stagingSiteId;
  const detail = await rocketGet(token, `/sites/${stagingId}`);
  const target: StagingTarget = {
    id: detail.id,
    domain: detail.domain,
    production: detail.production,
  };
  assertStagingTarget(target, parent);

  const memo = new Map<string, Promise<Map<string, RocketItem>>>();
  const once = (key: string, fn: () => Promise<Map<string, RocketItem>>) => {
    if (!memo.has(key)) memo.set(key, fn());
    return memo.get(key) as Promise<Map<string, RocketItem>>;
  };
  const rc: RunCtx = {
    token,
    target,
    parent,
    probe: makeProbe(token, target, parent),
    actions,
    staging: s => once(`staging:${s}`, () => siteList(token, stagingId, s)),
    // Read-only: production versions, to spot staging lag / already-fixed.
    prod: s =>
      once(`prod:${s}`, () =>
        siteList(token, parent.rocketSiteId, s).catch(
          () => new Map<string, RocketItem>(),
        ),
      ),
    planThemeFor: async (theme, plugin) => {
      const label = plugin.name ?? plugin.slug;
      let t = actions.find(
        x => x.kind === "update_theme" && x.slug === theme.name,
      );
      if (!t) {
        const stg = (await rc.staging("themes").catch(() => undefined))?.get(
          theme.name,
        );
        const offered =
          (!!stg?.update && stg.update !== "none") ||
          theme.update === "available";
        if (!stg || !offered) return false;
        t = {
          kind: "update_theme",
          slug: theme.name,
          name: stg.title || theme.title,
          fromVersion: stg.version,
          status: "pending",
        };
        actions.push(t);
      }
      if (!t.covers?.includes(label)) t.covers = [...(t.covers ?? []), label];
      return true;
    },
  };

  // Plugins first: diagnosing them can add theme updates for bundled plugins.
  await runPass(
    rc,
    actions.filter(a => sourceOf(a) === "plugins"),
    "plugins",
    save,
  );
  await runPass(
    rc,
    actions.filter(a => sourceOf(a) === "themes"),
    "themes",
    save,
  );
}

/** Request every action in `list` (all from one source), then re-read
 *  staging until each change shows up. */
async function runPass(
  rc: RunCtx,
  list: FixAction[],
  source: Source,
  save: () => Promise<unknown>,
) {
  if (list.length === 0) return;
  const { token, target, parent } = rc;
  const before = await rc.staging(source);
  const prod = await rc.prod(source);

  const requested: FixAction[] = [];
  const responses = new Map<FixAction, UpdateResult>();
  for (const a of list) {
    const p = before.get(a.slug);
    if (!p) {
      Object.assign(a, { status: "skipped", note: "Not installed on staging" });
      continue;
    }
    a.prodVersion = prod.get(a.slug)?.version || a.fromVersion;
    a.fromVersion = p.version || a.fromVersion;
    a.name = p.title || a.name;
    try {
      if (isUpdate(a)) {
        const ok = alreadyFixed(a, p.version);
        if (ok) {
          Object.assign(a, { status: "skipped", ...ok });
          await save();
          continue;
        }
        let offered = !!p.update && p.update !== "none";
        if (!offered) {
          // Rocket.net's list can miss updates that a premium plugin's or
          // theme's own updater injects; WP-CLI sees more of them.
          const w =
            a.kind === "update_theme"
              ? (await rc.probe.themes())?.find(t => t.name === a.slug)
              : (await rc.probe.wpPlugins())?.get(a.slug);
          offered = w?.update === "available";
        }
        if (!offered) {
          Object.assign(a, {
            status: "skipped",
            ...(await diagnose(rc, a, p.version)),
          });
          await save();
          continue;
        }
        const res = await updateStaging(token, target, parent, source, a.slug);
        if (res.kind === "already") {
          Object.assign(a, {
            status: "skipped",
            ...(await diagnose(rc, a, p.version, res.message)),
          });
          await save();
          continue;
        }
        // Success or unclear: re-reading staging decides.
        responses.set(a, res);
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
      const msg = e instanceof Error ? e.message : String(e);
      if (msg.startsWith("Refusing Rocket.net write")) throw e;
      if (isUpdate(a)) {
        Object.assign(a, {
          status: "failed",
          note: undefined,
          ...(await diagnose(rc, a, p.version, msg)),
        });
      } else {
        Object.assign(a, { status: "failed", note: msg });
      }
    }
    await save();
  }

  // Re-read staging until each requested change shows up
  const applied = (a: FixAction, p?: RocketItem) =>
    !!p && (isUpdate(a) ? p.version !== a.fromVersion : p.status === "active");
  let waited = 0;
  for (let i = 0; i < VERIFY_DELAYS_MS.length && requested.length > 0; i++) {
    await new Promise(r => setTimeout(r, VERIFY_DELAYS_MS[i]));
    waited += VERIFY_DELAYS_MS[i];
    const after = await siteList(token, parent.stagingSiteId!, source).catch(
      () => null,
    );
    const last = i === VERIFY_DELAYS_MS.length - 1;
    if (!after) {
      if (last) throw new Error(`Couldn't re-read ${source} from staging`);
      continue;
    }
    for (const a of requested) a.toVersion = after.get(a.slug)?.version;
    if (requested.every(a => applied(a, after.get(a.slug))) || last) {
      for (const a of requested) {
        const p = after.get(a.slug);
        const res = responses.get(a);
        if (!applied(a, p)) {
          const shown = p?.version ?? a.fromVersion ?? "?";
          if (isUpdate(a) && res?.kind === "success") {
            // Never report Rocket.net's success message as an error.
            Object.assign(a, {
              status: "needs_check",
              note: undefined,
              tone: "attention",
              toVersion: undefined,
              reason: `Rocket.net reported the update as successful${res.newVersion ? ` (to v${res.newVersion})` : ""}, but staging still shows v${shown} after ${Math.round(waited / 1000)}s — re-run or check staging.`,
              detail: res.message
                ? `Rocket.net update response: ${res.message}`
                : undefined,
            });
          } else if (isUpdate(a)) {
            a.status = "failed";
            a.note = undefined;
            a.toVersion = undefined;
            Object.assign(
              a,
              await diagnose(
                rc,
                a,
                shown,
                `Rocket.net accepted the update but staging still reports v${shown}${res?.message ? `. Rocket.net response: ${res.message}` : ""}`,
              ),
            );
          } else {
            a.status = "failed";
            a.note =
              "Rocket.net accepted the request but the plugin is still inactive";
          }
        } else {
          a.status = "done";
          a.note = undefined;
          a.reason = undefined;
          a.detail = undefined;
          a.tone = undefined;
          a.note = doneNote(a);
        }
      }
      break;
    }
  }
}

/** Follow-up for a finished update, if any. */
export function doneNote(a: {
  kind: string;
  fixedIn?: string;
  toVersion?: string;
  covers?: string[];
}): string | undefined {
  const notes: string[] = [];
  if (a.fixedIn && a.toVersion && compareVersions(a.toVersion, a.fixedIn) < 0) {
    notes.push(`Updated, but still below the fixed version ${a.fixedIn}`);
  }
  if (a.kind === "update_theme" && a.covers?.length) {
    const list = a.covers.join(", ");
    notes.push(
      `The newer ${list} ships with this theme — install it from the theme's bundled-plugins page in wp-admin, or re-run Fix on staging`,
    );
  }
  return notes.length ? notes.join(". ") : undefined;
}

// ─── Why couldn't it update? ─────────────────────────────────

type Diagnosis = {
  reason: string;
  detail?: string;
  tone: "attention" | "ok";
  note?: undefined;
};

const DETAIL_MAX = 2000;
const clip = (s: string) =>
  s.length > DETAIL_MAX ? `${s.slice(0, DETAIL_MAX)}…` : s;

/** Staging already has the fix — nothing to update. */
function alreadyFixed(a: FixAction, version: string): Diagnosis | null {
  if (!a.fixedIn || !version || compareVersions(version, a.fixedIn) < 0)
    return null;
  const prodBehind =
    a.prodVersion && compareVersions(a.prodVersion, a.fixedIn) < 0;
  return {
    tone: "ok",
    reason: prodBehind
      ? `Already fixed on staging (v${version} ≥ ${a.fixedIn}). Production is still on v${a.prodVersion} — push staging live to apply the fix.`
      : `Already at or above the fixed version (${a.fixedIn}) — the vulnerability record looks stale; rescan.`,
  };
}

// Common WordPress / WP-CLI update failures → plain English ("{c}" is
// "plugin" or "theme")
const UPDATE_ERRORS: [RegExp, string][] = [
  [
    /update package not available|package could not be downloaded|download failed|no valid (license|purchase)|licen[cs]e|purchase code|\b40[13]\b|unauthori[sz]ed|forbidden/i,
    "Premium {c}: update package unavailable — license missing or expired",
  ],
  [
    /fatal error/i,
    "WordPress crashed (PHP fatal error) while updating — see details",
  ],
  [
    /disk quota|no space left/i,
    "Staging is out of disk space — free space and retry",
  ],
  [
    /could not (create|copy|remove)|permission denied/i,
    "WordPress couldn't write the {c} files on staging (file permissions)",
  ],
];

// Vendors that store license state in wp_options
const VENDOR_LICENSE: Record<
  string,
  { vendor: string; valid: string; latest: string }
> = {
  revslider: {
    vendor: "ThemePunch",
    valid: "revslider-valid",
    latest: "revslider-latest-version",
  },
  "essential-grid": {
    vendor: "ThemePunch",
    valid: "tp_eg_valid",
    latest: "tp_eg_latest-version",
  },
};

const stripTags = (s?: string) => (s ?? "").replace(/<[^>]*>/g, "").trim();

/** Map an update error to plain English, if it's a known one. */
function mapUpdateError(err: string, component: "plugin" | "theme") {
  return UPDATE_ERRORS.find(([re]) => re.test(err))?.[1].replace(
    /\{c\}/g,
    component,
  );
}

async function diagnose(
  rc: RunCtx,
  a: FixAction,
  version: string,
  updateError?: string,
): Promise<Diagnosis> {
  const facts: string[] = [];
  const reason =
    a.kind === "update_theme" ? diagnoseThemeReason : diagnoseReason;
  const d = await reason(rc, a, version, updateError, facts).catch(
    (e): Diagnosis => ({
      tone: "attention",
      reason: `No update offered on staging (v${version})`,
      detail: `Diagnostics failed: ${e instanceof Error ? e.message : String(e)}`,
    }),
  );
  if (a.prodVersion && version && compareVersions(version, a.prodVersion) < 0) {
    d.reason = `Staging is older than live (v${version} vs v${a.prodVersion}). Pushing this staging copy live would downgrade it — refresh staging from live first. ${d.reason}`;
  }
  const detail = [d.detail, ...facts].filter(Boolean).join("\n");
  return { ...d, detail: detail ? clip(detail) : undefined, note: undefined };
}

const attention = (reason: string, detail?: string): Diagnosis => ({
  tone: "attention",
  reason,
  detail,
});

async function diagnoseReason(
  rc: RunCtx,
  a: FixAction,
  version: string,
  updateError: string | undefined,
  facts: string[],
): Promise<Diagnosis> {
  const { probe } = rc;
  const already = updateError && ALREADY_RE.test(updateError);

  // 1. The actual error from the update attempt
  if (updateError && !already) {
    const mapped = mapUpdateError(updateError, "plugin");
    return attention(
      mapped ?? "Rocket.net couldn't update it — error below",
      updateError,
    );
  }
  if (already) facts.push(`Rocket.net update response: ${updateError}`);

  const org = await probe.wporg(a.slug);

  // 2. No fix released
  if (!a.fixedIn) {
    if (org.kind === "closed") {
      return attention(
        `Plugin was closed on wordpress.org${org.when ? ` (${org.when})` : ""} and no fixed version was released — replace or remove it.`,
        org.why,
      );
    }
    return attention(
      "No fixed version has been released for this vulnerability — consider replacing or removing the plugin.",
    );
  }

  // 3. Closed on wordpress.org
  if (org.kind === "closed") {
    return attention(
      `Plugin was closed on wordpress.org${org.when ? ` (${org.when})` : ""} — no updates will come; replace it.`,
      org.why,
    );
  }

  // 4. Bundled with the active theme
  const wp = (await probe.wpPlugins())?.get(a.slug);
  const author = stripTags(wp?.author).toLowerCase();
  const themes = (await probe.themes()) ?? [];
  const theme =
    org.kind !== "listed" && author
      ? themes.find(
          t =>
            (t.status === "active" || t.status === "parent") &&
            stripTags(t.author).toLowerCase() === author,
        )
      : undefined;
  if (theme) {
    const root =
      themes.find(t => t.status === "parent" && t.author === theme.author) ??
      theme;
    const code = await probe.option(`purchase_code_${root.name}`);
    facts.push(
      code
        ? `Theme ${root.title ?? root.name} has a purchase code registered.`
        : `No purchase code registered for theme ${root.title ?? root.name} — its license may not be activated.`,
    );
    const planned = await rc.planThemeFor(root, a);
    return attention(
      bundledReason(
        `${root.title ?? root.name} (v${root.version ?? "?"}, ${stripTags(root.author)})`,
        a.fixedIn,
        planned,
      ),
    );
  }

  // 5. Premium / third-party
  const lic = VENDOR_LICENSE[a.slug];
  const name = a.name ?? a.slug;
  if (org.kind === "missing" || (org.kind === "unknown" && lic)) {
    if (lic) {
      const valid = await probe.option(lic.valid);
      const latest = await probe.option(lic.latest);
      if (latest) facts.push(`${lic.vendor} update server latest: v${latest}`);
      if (valid !== "true") {
        return attention(
          `License not activated on this site — activate the ${lic.vendor} license to receive updates${latest ? ` (vendor has v${latest})` : ""}.`,
          `${lic.valid} = ${valid ?? "(not set)"}`,
        );
      }
      if (latest && compareVersions(latest, version) <= 0) {
        return attention(
          `License is active, but ${lic.vendor}'s update server offers nothing newer than v${latest}${compareVersions(latest, a.fixedIn) < 0 ? ` — the fix (${a.fixedIn}) isn't available as an automatic update; install it manually from the vendor` : ""}.`,
        );
      }
      if (latest) {
        return attention(
          `License is active and ${lic.vendor} offers v${latest}, but WordPress on staging isn't offering it — run "Check again" in wp-admin → Updates.`,
        );
      }
    }
    if (org.kind === "missing") {
      // The premium build often lives in a different folder than the free
      // wordpress.org edition (wpforms vs wpforms-lite, …-premium vs base).
      const free = await probe.freeEdition(a.slug);
      if (free) {
        return attention(
          `Premium edition of ${name} — updates come from the vendor and need a valid license.`,
          `wordpress.org only has the free edition (${free.slug}${free.version ? `, v${free.version}` : ""}); "${a.slug}" isn't listed there.`,
        );
      }
      return attention(
        "Premium/third-party plugin, not on wordpress.org — updates come from the vendor and need a valid license.",
      );
    }
    return attention(
      "Couldn't check wordpress.org; if this is a premium plugin, updates need a valid vendor license.",
    );
  }

  // 6. Listed on wordpress.org
  if (org.kind === "listed" && org.version) {
    if (compareVersions(org.version, a.fixedIn) < 0) {
      return attention(
        `The latest release on wordpress.org (v${org.version}) doesn't include the fix (${a.fixedIn}) yet.`,
      );
    }
    if (compareVersions(org.version, version) > 0) {
      return attention(
        `wordpress.org has v${org.version}, but staging isn't offering it — updates may be blocked (plugin/version lock) or WordPress's update check is stale.`,
      );
    }
  }

  // 7. Fallback
  if (org.kind === "unknown") {
    facts.push(
      "Couldn't check wordpress.org (request failed), so whether this is a premium plugin is unknown.",
    );
  }
  return attention(
    `No update offered on staging (v${version}); latest known fix is ${a.fixedIn}.`,
    wp?.update_version
      ? `WP-CLI reports update ${wp.update_version}`
      : undefined,
  );
}

export function bundledReason(
  theme: string,
  fixedIn: string,
  planned: boolean,
): string {
  return planned
    ? `Bundled with the theme ${theme} — the theme update is planned below; the fix needs v${fixedIn}.`
    : `Bundled with the theme ${theme} — update the theme to get a newer version; the fix needs v${fixedIn}.`;
}

async function diagnoseThemeReason(
  rc: RunCtx,
  a: FixAction,
  version: string,
  updateError: string | undefined,
  facts: string[],
): Promise<Diagnosis> {
  const { probe } = rc;
  const already = updateError && ALREADY_RE.test(updateError);
  const covers = a.covers?.length
    ? ` (needed for the bundled ${a.covers.join(", ")})`
    : "";

  // 1. The actual error from the update attempt
  if (updateError && !already) {
    return attention(
      mapUpdateError(updateError, "theme") ??
        "Rocket.net couldn't update the theme — error below",
      updateError,
    );
  }
  if (already) facts.push(`Rocket.net update response: ${updateError}`);

  // 2. No fix released (and not here for a bundled plugin)
  if (!a.fixedIn && !covers) {
    return attention(
      "No fixed version has been released for this vulnerability — consider replacing the theme.",
    );
  }

  const org = await probe.wporgTheme(a.slug);
  const name = a.name ?? a.slug;

  // 3. Premium / third-party
  if (org.kind === "missing") {
    const code = await probe.option(`purchase_code_${a.slug}`);
    facts.push(
      code
        ? `Theme ${name} has a purchase code registered.`
        : `No purchase code registered for theme ${name} — its license may not be activated.`,
    );
    return attention(
      `Premium/third-party theme, not on wordpress.org — updates come from the theme vendor and need a registered purchase code or license${covers}.`,
    );
  }

  // 4. Listed on wordpress.org
  if (org.kind === "listed" && org.version) {
    if (a.fixedIn && compareVersions(org.version, a.fixedIn) < 0) {
      return attention(
        `The latest release on wordpress.org (v${org.version}) doesn't include the fix (${a.fixedIn}) yet.`,
      );
    }
    if (compareVersions(org.version, version) > 0) {
      return attention(
        `wordpress.org has v${org.version}, but staging isn't offering it — WordPress's update check may be stale.`,
      );
    }
  }

  // 5. Fallback
  if (org.kind === "unknown") {
    facts.push(
      "Couldn't check wordpress.org (request failed), so whether this is a premium theme is unknown.",
    );
  }
  return attention(
    `No theme update offered on staging (v${version})${a.fixedIn ? `; latest known fix is ${a.fixedIn}` : ""}${covers}.`,
  );
}

// ─── Staging probe (read-only WP-CLI + wordpress.org) ────────

type WpCliPlugin = {
  name: string;
  version?: string;
  update?: string;
  update_version?: string;
  author?: string;
};
type WpCliTheme = {
  name: string;
  title?: string;
  status?: string;
  version?: string;
  author?: string;
  update?: string;
  update_version?: string;
};
type OrgInfo =
  | { kind: "listed"; version?: string }
  | { kind: "closed"; when?: string; why?: string }
  | { kind: "missing" }
  | { kind: "unknown" };

type Probe = ReturnType<typeof makeProbe>;

function makeProbe(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
) {
  const memo = new Map<string, Promise<unknown>>();
  const once = <T>(key: string, fn: () => Promise<T>): Promise<T> => {
    if (!memo.has(key))
      memo.set(
        key,
        fn().catch(() => undefined),
      );
    return memo.get(key) as Promise<T>;
  };
  const cli = (cmd: string) => stagingWpCli(token, target, parent, cmd);

  return {
    /** WP-CLI plugin list with plugins loaded, so premium updaters run. */
    wpPlugins: () =>
      once("plugins", async () => {
        const list = await cliJsonSkippingFatals<WpCliPlugin[]>(
          cli,
          "plugin list --fields=name,version,update,update_version,author --format=json",
        );
        return list ? new Map(list.map(p => [p.name, p])) : undefined;
      }),
    themes: () =>
      once("themes", () =>
        cliJsonSkippingFatals<WpCliTheme[]>(
          cli,
          "theme list --fields=name,title,status,version,author,update,update_version --format=json --skip-plugins",
        ),
      ),
    /** undefined = couldn't read; null = option not set */
    option: (name: string) =>
      once(`opt:${name}`, async () => {
        const out = await cli(
          `option get ${name} --format=json --skip-plugins --skip-themes`,
        );
        if (/^Error:/m.test(out)) return null;
        const v = parseCliJson(out);
        return v === undefined || v === null
          ? null
          : typeof v === "string"
            ? v
            : JSON.stringify(v);
      }) as Promise<string | null | undefined>,
    wporg: (slug: string) =>
      once(`org:${slug}`, () => wporgInfo(slug)).then(
        (x): OrgInfo => x ?? { kind: "unknown" },
      ),
    wporgTheme: (slug: string) =>
      once(`orgtheme:${slug}`, () => wporgInfo(slug, "themes")).then(
        (x): OrgInfo => x ?? { kind: "unknown" },
      ),
    /** The free wordpress.org edition of a premium slug, if one is listed. */
    freeEdition: async (slug: string) => {
      const candidates = [
        `${slug}-lite`,
        slug.replace(/-(premium|pro)$/, ""),
      ].filter(c => c !== slug);
      for (const c of candidates) {
        const info = await once(`org:${c}`, () => wporgInfo(c));
        if (info?.kind === "listed") return { slug: c, version: info.version };
      }
      return undefined;
    },
  };
}

/** Parse the JSON a WP-CLI command printed, ignoring PHP warnings around it. */
function parseCliJson(out: string): unknown {
  try {
    return JSON.parse(out.trim());
  } catch {}
  const lines = out.split("\n").reverse();
  for (const l of lines) {
    const t = l.trim();
    if (!/^[[{"]/.test(t)) continue;
    try {
      return JSON.parse(t);
    } catch {}
  }
  return undefined;
}

// A plugin that fatals under WP-CLI breaks every command; skip it and retry.
async function cliJsonSkippingFatals<T>(
  cli: (cmd: string) => Promise<string>,
  cmd: string,
): Promise<T | undefined> {
  const skip: string[] = [];
  for (let i = 0; i < 3; i++) {
    const out = await cli(
      skip.length ? `${cmd} --skip-plugins=${skip.join(",")}` : cmd,
    );
    const fatal = out.match(
      /Fatal error:.*?wp-content\/plugins\/([A-Za-z0-9_.-]+)\//,
    );
    if (fatal && !skip.includes(fatal[1])) {
      skip.push(fatal[1]);
      continue;
    }
    return parseCliJson(out) as T | undefined;
  }
  return undefined;
}

async function wporgInfo(
  slug: string,
  dir: "plugins" | "themes" = "plugins",
): Promise<OrgInfo> {
  const what = dir === "themes" ? "theme" : "plugin";
  const url = `https://api.wordpress.org/${dir}/info/1.2/?action=${what}_information&request[slug]=${encodeURIComponent(slug)}&request[fields][sections]=0`;
  try {
    const resp = await fetch(url, {
      headers: { "User-Agent": "SecurityManager/1.0" },
    });
    const body = (await resp.json()) as {
      error?: string;
      version?: string;
      closed_date?: string;
      reason_text?: string;
      description?: string;
    };
    if (body.error === "closed") {
      return {
        kind: "closed",
        when: body.closed_date?.slice(0, 10),
        why: body.reason_text
          ? `Closure reason: ${stripTags(body.reason_text)}`
          : stripTags(body.description) || undefined,
      };
    }
    // Only a definite "not found" means it isn't on wordpress.org; rate
    // limits, outages and odd responses stay "unknown".
    if (body.error)
      return resp.status === 404 || /not found/i.test(body.error)
        ? { kind: "missing" }
        : { kind: "unknown" };
    return resp.ok && body.version
      ? { kind: "listed", version: body.version }
      : { kind: "unknown" };
  } catch {
    return { kind: "unknown" };
  }
}

// ─── Rocket.net API ──────────────────────────────────────────

/** A row of GET /sites/{id}/plugins or /themes (same shape for both;
 *  theme status is "active" | "parent" | "inactive"). */
type RocketItem = {
  name: string;
  status: string;
  version: string;
  update?: string;
  update_version?: string;
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

async function siteList(
  token: string,
  siteId: number,
  source: Source,
): Promise<Map<string, RocketItem>> {
  const resp = await rocketFetch(
    `${ROCKET_API_BASE}/sites/${siteId}/${source}`,
    { headers: rocketHeaders(token) },
  );
  if (!resp.ok)
    throw new Error(
      `Rocket.net GET /sites/${siteId}/${source} failed (${resp.status})`,
    );
  const body = (await resp.json()) as { result?: RocketItem[] };
  return new Map((body.result ?? []).map(p => [p.name, p]));
}

type RocketEnvelope = {
  success?: boolean;
  messages?: string[];
  errors?: unknown[];
  result?: unknown;
};

/** The only code path that sends a write request to Rocket.net. */
async function stagingWrite(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  method: "PUT" | "PATCH" | "POST",
  subpath: string,
  body: Record<string, unknown>,
): Promise<RocketEnvelope> {
  const id = assertStagingTarget(target, parent);
  const resp = await rocketFetch(`${ROCKET_API_BASE}/sites/${id}${subpath}`, {
    method,
    headers: { ...rocketHeaders(token), "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const text = await resp.text();
  let json: RocketEnvelope = {};
  try {
    json = JSON.parse(text) as RocketEnvelope;
  } catch {}
  if (!resp.ok || json.success === false) {
    const msg = [...(json.messages ?? []), ...(json.errors ?? []).map(String)]
      .filter(Boolean)
      .join("; ");
    throw new Error(
      `Rocket.net ${method} ${subpath} failed (${resp.status}): ${msg || text.slice(0, 300)}`,
    );
  }
  return json;
}

// Confirmed 2026-09-30 against staging 282768 (rel "update_site_plugin"):
// PUT /sites/{id}/plugins {"plugin": "<slug>"} → 200
// {"result":[{"name","old_version","new_version","note"}]}; with nothing to
// update, note is "Plugin already updated" and the versions are empty.
// 2026-10-01 on staging 249687: real updates came back with note "Plugin
// updated successfully" (versions not reliably filled) and had already been
// applied — the activity log showed each one before the next PUT was sent.
type UpdateResult = {
  /** already: nothing to update; success: Rocket.net says it updated;
   *  other: no clear signal either way. */
  kind: "already" | "success" | "other";
  message?: string;
  newVersion?: string;
};

// Confirmed 2026-10-02 against staging 282768 (rel "update_site_theme"):
// PUT /sites/{id}/themes {"theme": "<slug>"} → 200
// {"result":[{"name":"bugster","old_version":"","new_version":"",
// "note":"Theme already updated"}]} for a theme with no update; the theme
// list was unchanged afterwards. Same row shape as plugins.
async function updateStaging(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  source: Source,
  slug: string,
): Promise<UpdateResult> {
  const res = await stagingWrite(
    token,
    target,
    parent,
    "PUT",
    `/${source}`,
    source === "themes" ? { theme: slug } : { plugin: slug },
  );
  return classifyUpdate(res, slug);
}

/** Classify a PUT /plugins or /themes response. */
export function classifyUpdate(
  res: RocketEnvelope,
  slug: string,
): UpdateResult {
  const rows = Array.isArray(res.result)
    ? (res.result as {
        name?: string;
        old_version?: string;
        new_version?: string;
        note?: string;
      }[])
    : [];
  const row = rows.find(r => r.name === slug) ?? rows[0];
  const newVersion = row?.new_version || undefined;
  const changed = !!newVersion && newVersion !== row?.old_version;
  const message =
    row?.note || [...(res.messages ?? [])].filter(Boolean).join("; ");
  const kind =
    changed || /success|updated to/i.test(message)
      ? "success"
      : ALREADY_RE.test(message)
        ? "already"
        : "other";
  return { kind, message: message || undefined, newVersion };
}

// Confirmed 2026-10-01 against staging 306474 (rel "toggle_plugin_status"):
// PATCH /sites/{id}/plugins {"plugin": "<slug>", "status": "activate"} → 200
// {"result":[{"name","activated":"true"}]}. "status" must be "activate" or
// "deactivate"; GET /plugins then reports the plugin's status as "active".
function activateStagingPlugin(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  slug: string,
) {
  return stagingWrite(token, target, parent, "PATCH", "/plugins", {
    plugin: slug,
    status: "activate",
  });
}

// Read-only WP-CLI commands the diagnostics may run on staging.
const WPCLI_ALLOWED = /^(plugin (list|get)|theme (list|get)|option get) /;

/**
 * POST /sites/{id}/wpcli {"command": "<args without wp>"} (confirmed
 * 2026-09-30). The response's result.response is a JSON string whose
 * "data" holds WP-CLI's combined output. Goes through the staging guard
 * like every other POST, and only allows read-only commands.
 */
async function stagingWpCli(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  command: string,
): Promise<string> {
  if (!WPCLI_ALLOWED.test(command) || /[;&|`$<>]/.test(command))
    throw new Error(`WP-CLI command not allowed: ${command}`);
  const res = await stagingWrite(token, target, parent, "POST", "/wpcli", {
    command,
  });
  const raw = (res.result as { response?: unknown } | undefined)?.response;
  if (typeof raw !== "string") return "";
  try {
    const inner = JSON.parse(raw) as { data?: unknown };
    return typeof inner.data === "string"
      ? inner.data
      : String(inner.data ?? "");
  } catch {
    return raw;
  }
}
