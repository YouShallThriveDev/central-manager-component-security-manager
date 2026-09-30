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
      prodVersion: x.pluginVersion,
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
      .map(a => {
        const why = a.reason ?? a.note;
        return `${a.slug}: ${a.status}${why ? ` (${why})` : ""}`;
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

  const before = await sitePlugins(token, parent.stagingSiteId);
  // Read-only: production versions, to spot staging lag / already-fixed.
  const prod = await sitePlugins(token, parent.rocketSiteId).catch(
    () => new Map<string, RocketPlugin>(),
  );
  const probe = makeProbe(token, target, parent);

  const requested: FixAction[] = [];
  for (const a of actions) {
    const p = before.get(a.slug);
    if (!p) {
      Object.assign(a, { status: "skipped", note: "Not installed on staging" });
      continue;
    }
    a.prodVersion = prod.get(a.slug)?.version || a.fromVersion;
    a.fromVersion = p.version || a.fromVersion;
    a.name = p.title || a.name;
    try {
      if (a.kind === "update_plugin") {
        const ok = alreadyFixed(a, p.version);
        if (ok) {
          Object.assign(a, { status: "skipped", ...ok });
          await save();
          continue;
        }
        let offered = !!p.update && p.update !== "none";
        if (!offered) {
          // Rocket.net's list can miss updates that a premium plugin's own
          // updater injects; WP-CLI with plugins loaded sees them.
          const w = (await probe.wpPlugins())?.get(a.slug);
          offered = w?.update === "available";
        }
        if (!offered) {
          Object.assign(a, {
            status: "skipped",
            ...(await diagnose(probe, a, p.version)),
          });
          await save();
          continue;
        }
        const res = await updateStagingPlugin(token, target, parent, a.slug);
        if (!res.changed) {
          Object.assign(a, {
            status: "skipped",
            ...(await diagnose(probe, a, p.version, res.message)),
          });
          await save();
          continue;
        }
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
      if (a.kind === "update_plugin") {
        Object.assign(a, {
          status: "failed",
          note: undefined,
          ...(await diagnose(probe, a, p.version, msg)),
        });
      } else {
        Object.assign(a, { status: "failed", note: msg });
      }
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
    const after = await sitePlugins(token, parent.stagingSiteId);
    for (const a of requested) a.toVersion = after.get(a.slug)?.version;
    if (
      requested.every(a => applied(a, after.get(a.slug))) ||
      i === VERIFY_ATTEMPTS - 1
    ) {
      for (const a of requested) {
        const p = after.get(a.slug);
        if (!applied(a, p)) {
          a.status = "failed";
          if (a.kind === "update_plugin") {
            a.note = undefined;
            Object.assign(
              a,
              await diagnose(
                probe,
                a,
                p?.version ?? a.fromVersion ?? "",
                `Rocket.net accepted the update but staging still reports v${p?.version ?? "?"}`,
              ),
            );
          } else {
            a.note =
              "Rocket.net accepted the request but the plugin is still inactive";
          }
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

// Common WordPress / WP-CLI update failures → plain English
const UPDATE_ERRORS: [RegExp, string][] = [
  [
    /update package not available|package could not be downloaded|download failed|no valid (license|purchase)|licen[cs]e|purchase code|\b40[13]\b|unauthori[sz]ed|forbidden/i,
    "Premium plugin: update package unavailable — license missing or expired",
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
    "WordPress couldn't write the plugin files on staging (file permissions)",
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

async function diagnose(
  probe: Probe,
  a: FixAction,
  version: string,
  updateError?: string,
): Promise<Diagnosis> {
  const facts: string[] = [];
  const d = await diagnoseReason(probe, a, version, updateError, facts).catch(
    (e): Diagnosis => ({
      tone: "attention",
      reason: `No update offered on staging (v${version})`,
      detail: `Diagnostics failed: ${e instanceof Error ? e.message : String(e)}`,
    }),
  );
  if (a.prodVersion && version && compareVersions(version, a.prodVersion) < 0) {
    d.reason += ` Staging (v${version}) is behind production (v${a.prodVersion}) — refresh staging from live first.`;
  }
  const detail = [d.detail, ...facts].filter(Boolean).join("\n");
  return { ...d, detail: detail ? clip(detail) : undefined, note: undefined };
}

async function diagnoseReason(
  probe: Probe,
  a: FixAction,
  version: string,
  updateError: string | undefined,
  facts: string[],
): Promise<Diagnosis> {
  const attention = (reason: string, detail?: string): Diagnosis => ({
    tone: "attention",
    reason,
    detail,
  });
  const already = updateError && /already updated/i.test(updateError);

  // 1. The actual error from the update attempt
  if (updateError && !already) {
    const mapped = UPDATE_ERRORS.find(([re]) => re.test(updateError))?.[1];
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
    return attention(
      `Bundled with the theme ${root.title ?? root.name} (v${root.version ?? "?"}, ${stripTags(root.author)}) — update the theme to get a newer version; the fix needs v${a.fixedIn}.`,
    );
  }

  // 5. Premium / third-party
  const lic = VENDOR_LICENSE[a.slug];
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
    return attention(
      "Premium/third-party plugin, not on wordpress.org — updates need a valid vendor license.",
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
  return attention(
    `No update offered on staging (v${version}); latest known fix is ${a.fixedIn}.`,
    wp?.update_version
      ? `WP-CLI reports update ${wp.update_version}`
      : undefined,
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
          "theme list --fields=name,title,status,version,author --format=json --skip-plugins",
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

async function wporgInfo(slug: string): Promise<OrgInfo> {
  const url = `https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request[slug]=${encodeURIComponent(slug)}&request[fields][sections]=0`;
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
    if (body.error) return { kind: "missing" };
    return resp.ok
      ? { kind: "listed", version: body.version }
      : { kind: "unknown" };
  } catch {
    return { kind: "unknown" };
  }
}

// ─── Rocket.net API ──────────────────────────────────────────

type RocketPlugin = {
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

async function sitePlugins(
  token: string,
  siteId: number,
): Promise<Map<string, RocketPlugin>> {
  const resp = await rocketFetch(`${ROCKET_API_BASE}/sites/${siteId}/plugins`, {
    headers: rocketHeaders(token),
  });
  if (!resp.ok)
    throw new Error(
      `Rocket.net GET /sites/${siteId}/plugins failed (${resp.status})`,
    );
  const body = (await resp.json()) as { result?: RocketPlugin[] };
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
async function updateStagingPlugin(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  slug: string,
): Promise<{ changed: boolean; message?: string }> {
  const res = await stagingWrite(token, target, parent, "PUT", "/plugins", {
    plugin: slug,
  });
  const rows = Array.isArray(res.result)
    ? (res.result as {
        name?: string;
        old_version?: string;
        new_version?: string;
        note?: string;
      }[])
    : [];
  const row = rows.find(r => r.name === slug) ?? rows[0];
  const changed = !!row?.new_version && row.new_version !== row.old_version;
  const message =
    row?.note || [...(res.messages ?? [])].filter(Boolean).join("; ");
  // No per-plugin row: let the verify step decide.
  return { changed: changed || !row, message: message || undefined };
}

// Endpoint + method confirmed from the site's own API links
// (rel "toggle_plugin_status": PATCH /sites/{id}/plugins).
// TODO(unconfirmed): body — "plugin" mirrors the confirmed PUT schema;
// "action" is a guess. The verify step re-reads staging, so a no-op shows
// as failed, and a 400 surfaces Rocket.net's validation message.
function activateStagingPlugin(
  token: string,
  target: StagingTarget,
  parent: StagingParent,
  slug: string,
) {
  return stagingWrite(token, target, parent, "PATCH", "/plugins", {
    plugin: slug,
    action: "activate",
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
