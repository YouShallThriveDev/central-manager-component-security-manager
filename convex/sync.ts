import { calculateSecurityScore } from "./securityScore";
import { isStagingDomain } from "./stagingGuard";
/**
 * Sync actions — pull production site data from Rocket.net API and
 * analyze security posture.
 */
import { v } from "convex/values";
import { action, internalAction } from "./_generated/server";
import { internal } from "./_generated/api";

const ROCKET_API_BASE = "https://api.rocket.net/v1";

// ─── Security Plugin Categorization ──────────────────────────

type SecurityCategory =
  | "firewall"
  | "malware"
  | "brute-force"
  | "two-factor"
  | "backup"
  | "general-security"
  | "monitoring";

const SECURITY_PLUGINS: Record<string, SecurityCategory> = {
  // Firewall / WAF
  wordfence: "firewall",
  "wordfence-assistant": "firewall",
  "sucuri-scanner": "firewall",
  "all-in-one-wp-security-and-firewall": "firewall",
  "better-wp-security": "firewall", // iThemes Security
  "ithemes-security": "firewall",
  "ithemes-security-pro": "firewall",
  patchstack: "firewall",
  "wp-cerber": "firewall",
  "shield-security": "firewall",
  "ninja-firewall": "firewall",

  // Malware scanning
  "malcare-security": "malware",
  "anti-malware-security-and-brute-force-firewall": "malware",
  "gotmls": "malware",
  "wordfence-scan": "malware",
  "sucuri-scanner-free": "malware",

  // Brute force protection
  "limit-login-attempts-reloaded": "brute-force",
  "login-lockdown": "brute-force",
  "loginizer": "brute-force",
  "wp-limit-login-attempts": "brute-force",

  // Two-factor authentication
  "two-factor-authentication": "two-factor",
  "wp-2fa": "two-factor",
  "google-authenticator": "two-factor",
  "miniorange-2-factor-authentication": "two-factor",
  "duo-wordpress": "two-factor",

  // Backup
  updraftplus: "backup",
  "backwpup": "backup",
  "wpvivid-backup-plugin": "backup",
  "duplicator": "backup",
  "duplicator-pro": "backup",
  "backup-backup": "backup",
  "blogvault-real-time-backup": "backup",

  // General security
  jetpack: "general-security",
  "jetpack-protect": "general-security",
  "defender-security": "general-security",
  "security-ninja": "general-security",
  "bulletproof-security": "general-security",
  "headers-security-advanced-hsts-wp": "general-security",
  "really-simple-ssl": "general-security",
  "really-simple-ssl-pro": "general-security",

  // Monitoring / Activity
  "wp-security-audit-log": "monitoring",
  "simple-history": "monitoring",
  "activity-log": "monitoring",
  "stream": "monitoring",
  "wp-activity-log": "monitoring",
  "wp-health": "monitoring",
};

const SECURITY_MU_PLUGINS = new Set([
  "_patchstack.php",
  "wordfence-waf.php",
  "0-sg-security.php",
  "sucuri-firewall.php",
]);

function getSecurityCategory(
  slug: string,
): SecurityCategory | null {
  return SECURITY_PLUGINS[slug] ?? null;
}

// isSecurityPlugin is used via the SECURITY_PLUGINS map directly

// ─── Security Scoring ─────────────────────────────────────────

// ─── Rocket.net API Helpers ───────────────────────────────────

// Retry once on 401 — Rocket.net occasionally returns a transient 401 mid-sync.
async function rocketFetch(url: string, init: RequestInit): Promise<Response> {
  const resp = await fetch(url, init);
  if (resp.status !== 401) return resp;
  await new Promise((r) => setTimeout(r, 1500));
  return await fetch(url, init);
}

async function rocketGet(
  token: string,
  path: string,
  params?: Record<string, string>,
): Promise<Record<string, unknown>> {
  const url = new URL(`${ROCKET_API_BASE}${path}`);
  if (params) {
    for (const [k, val] of Object.entries(params)) {
      url.searchParams.set(k, val);
    }
  }

  const resp = await rocketFetch(url.toString(), {
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
      "User-Agent": "Mozilla/5.0 (compatible; SecurityManager/1.0)",
    },
  });

  if (!resp.ok) {
    if (resp.status === 401) {
      throw new Error(
        `Sync error (401 from Rocket.net). Check the sync logs for details.`,
      );
    }
    if (resp.status === 403) {
      throw new Error(
        `Sync error (403 from Rocket.net). Check the sync logs for details.`,
      );
    }
    throw new Error(`Sync error (${resp.status} from Rocket.net). Check the sync logs for details.`);
  }

  return (await resp.json()) as Record<string, unknown>;
}

async function fetchAllSites(
  token: string,
): Promise<Array<Record<string, unknown>>> {
  const allSites: Array<Record<string, unknown>> = [];
  let page = 1;
  while (true) {
    const body = await rocketGet(token, "/sites", {
      page: String(page),
      per_page: "100",
    });
    const sites = (body.result ?? []) as Array<Record<string, unknown>>;
    allSites.push(...sites);
    if (sites.length < 100) break;
    page++;
  }
  return allSites;
}

async function fetchSitePlugins(
  token: string,
  siteId: number,
): Promise<Array<Record<string, unknown>>> {
  const body = await rocketGet(token, `/sites/${siteId}/plugins`);
  return (body.result ?? []) as Array<Record<string, unknown>>;
}

// GET /sites/{id}/themes → result: [{ name, status ("active" | "parent" |
// "inactive"), version, update ("none" | "available"), update_version, title,
// description }] (checked 2026-10-02 on 175507 / staging 282768).
async function fetchSiteThemes(
  token: string,
  siteId: number,
): Promise<Array<Record<string, unknown>>> {
  const body = await rocketGet(token, `/sites/${siteId}/themes`);
  return (body.result ?? []) as Array<Record<string, unknown>>;
}

async function fetchMuPlugins(
  token: string,
  siteId: number,
): Promise<Array<Record<string, unknown>>> {
  const body = await rocketGet(token, `/sites/${siteId}/files`, {
    path: "/wp-content/mu-plugins",
  });
  const result = (body.result ?? body) as Record<string, unknown>;
  return (result.files ?? []) as Array<Record<string, unknown>>;
}

async function fetchSiteDetails(
  token: string,
  siteId: number,
): Promise<Record<string, unknown>> {
  const body = await rocketGet(token, `/sites/${siteId}`);
  return (body.result ?? body) as Record<string, unknown>;
}

// Parent sites reference their staging copy as staging.staging_id
function stagingIdOf(site: Record<string, unknown>): number | null {
  const id = (site.staging as { staging_id?: unknown } | undefined)?.staging_id;
  return typeof id === "number" && id > 0 ? id : null;
}

// Token retrieval is done inline in doFullSync

// ─── Progress Tracking ───────────────────────────────────────

async function setProgress(
  ctx: { runMutation: (ref: any, args: any) => Promise<any> },
  progress: {
    status: "syncing" | "idle" | "error" | "done";
    phase: string;
    total: number;
    completed: number;
    currentSite?: string;
    errors: number;
    errorSites?: string[];
  },
) {
  await ctx.runMutation(internal.settings.setInternal, {
    key: "sync_progress",
    value: JSON.stringify(progress),
  });
}

// ─── Site Scanning ────────────────────────────────────────────

async function scanSiteSecurity(
  ctx: { runMutation: (ref: any, args: any) => Promise<any> },
  token: string,
  docId: string,
  rocketSiteId: number,
  accountId?: string,
  domain?: string,
) {
  // Fetch site details
  let phpVersion: string | undefined;
  let sslEnabled = true; // Rocket.net has SSL by default
  try {
    const details = await fetchSiteDetails(token, rocketSiteId);
    phpVersion = details.php_version as string | undefined;
    if (details.ssl !== undefined) {
      sslEnabled = !!details.ssl;
    }
  } catch {
    // non-critical
  }

  // Fetch plugins
  const rawPlugins = await fetchSitePlugins(token, rocketSiteId);
  const plugins = rawPlugins.map((p) => {
    const slug = (p.name as string) ?? "";
    const status = (p.status as string) ?? "inactive";
    const cat = getSecurityCategory(slug);
    return {
      slug,
      displayName: (p.title as string) ?? slug,
      status:
        status === "must-use"
          ? ("must-use" as const)
          : status === "active"
            ? ("active" as const)
            : ("inactive" as const),
      version: p.version as string | undefined,
      updateAvailable:
        p.update !== "none" &&
        p.update !== undefined &&
        p.update !== null &&
        p.update !== "",
      isSecurityPlugin: cat !== null,
      securityCategory: cat,
    };
  });

  // Fetch themes (scanned for vulnerabilities like plugins). null = the
  // request failed, so the stored list is kept rather than wiped.
  let themes: Array<{
    slug: string;
    displayName?: string;
    status: string;
    version?: string;
    updateAvailable: boolean;
    updateVersion?: string;
  }> | null = null;
  try {
    const rawThemes = await fetchSiteThemes(token, rocketSiteId);
    themes = rawThemes
      .filter((t) => typeof t.name === "string" && t.name)
      .map((t) => ({
        slug: t.name as string,
        displayName: (t.title as string | undefined) || (t.name as string),
        status: (t.status as string | undefined) ?? "inactive",
        version: (t.version as string | undefined) || undefined,
        updateAvailable:
          t.update !== "none" &&
          t.update !== undefined &&
          t.update !== null &&
          t.update !== "",
        updateVersion: (t.update_version as string | undefined) || undefined,
      }));
  } catch {
    /* non-critical */
  }

  // Fetch MU-plugins
  let rawMuPlugins: Array<Record<string, unknown>> = [];
  try {
    rawMuPlugins = await fetchMuPlugins(token, rocketSiteId);
  } catch {
    /* ignore */
  }

  const muPlugins = rawMuPlugins.map((f) => {
    const filename = (f.file as string) ?? (f.name as string) ?? "";
    return {
      filename,
      present: true,
      isSecurityRelated: SECURITY_MU_PLUGINS.has(filename),
    };
  });

  // Analyze security posture
  const activeSecurityPlugins = plugins.filter(
    (p) => p.isSecurityPlugin && p.status === "active",
  );
  const activeCategories = new Set(
    activeSecurityPlugins.map((p) => p.securityCategory),
  );

  const hasFirewall = activeCategories.has("firewall");
  // Dedicated malware scanners, or comprehensive suites that include scanning
  const hasMalwareScanner =
    activeCategories.has("malware") ||
    activeSecurityPlugins.some((p) =>
      ["wordfence", "sucuri-scanner", "malcare-security", "ithemes-security-pro", "defender-security"].includes(p.slug),
    );
  const hasBackup = activeCategories.has("backup");
  const hasTwoFactor = activeCategories.has("two-factor");
  // Dedicated brute-force plugins, or specific firewalls known to include it
  const hasBruteForceProtection =
    activeCategories.has("brute-force") ||
    activeSecurityPlugins.some((p) =>
      ["wordfence", "sucuri-scanner", "all-in-one-wp-security-and-firewall", "ithemes-security", "ithemes-security-pro", "wp-cerber", "shield-security"].includes(p.slug),
    );

  const pluginsNeedingUpdate = plugins.filter((p) => p.updateAvailable).length;
  const totalPlugins = plugins.length;

  // Wordfence specifics
  const wordfencePlugin = plugins.find((p) => p.slug === "wordfence");
  const wordfenceInstalled = !!wordfencePlugin;
  const wordfenceActive = wordfencePlugin?.status === "active";
  const wordfenceVersion = wordfencePlugin?.version;

  // Calculate security score
  const { score, grade } = calculateSecurityScore({
    hasFirewall,
    hasMalwareScanner,
    hasBackup,
    hasTwoFactor,
    hasBruteForceProtection,
    pluginsNeedingUpdate,
    totalPlugins,
    sslEnabled,
    wordfenceActive,
    wordfenceInstalled,
  }, { critical: 0, high: 0, medium: 0, low: 0 });

  // Save plugin data
  await ctx.runMutation(internal.sitePlugins.batchUpsert, {
    siteId: docId as any,
    plugins: plugins.map((p) => ({
      slug: p.slug,
      displayName: p.displayName,
      status: p.status,
      version: p.version,
      updateAvailable: p.updateAvailable,
      isSecurityPlugin: p.isSecurityPlugin,
      securityCategory: p.securityCategory ?? undefined,
    })),
  });

  if (themes) {
    await ctx.runMutation(internal.siteThemes.batchUpsert, {
      siteId: docId as any,
      themes,
    });
  }

  // Save MU-plugin data
  await ctx.runMutation(internal.siteMuPlugins.batchUpsert, {
    siteId: docId as any,
    muPlugins,
  });

  // Update site record
  await ctx.runMutation(internal.sites.upsert, {
    accountId: accountId as any,
    rocketSiteId,
    domain: domain ?? "",
    phpVersion,
    sslEnabled,
    securityScore: score,
    securityGrade: grade,
    activeSecurityPlugins: activeSecurityPlugins.length,
    totalPlugins,
    pluginsNeedingUpdate,
    hasFirewall,
    hasMalwareScanner,
    hasBackup,
    hasTwoFactor,
    hasBruteForceProtection,
    wordfenceInstalled,
    wordfenceActive,
    wordfenceVersion,
  });

  return {
    pluginCount: plugins.length,
    securityPluginCount: activeSecurityPlugins.length,
    score,
    grade,
  };
}

// ─── Public Actions ──────────────────────────────────────────

export const syncEverything = action({
  args: {},
  returns: v.object({
    sitesSynced: v.number(),
    sitesScanned: v.number(),
    errors: v.number(),
  }),
  handler: async (ctx) => {
    // Pull latest credentials from Server Management first
    const credResult = await ctx.runAction(internal.credentialSync.pullFromServerManagement, {});
    if (credResult.error) {
      console.warn("Credential sync warning:", credResult.error);
    }

    const accounts = await ctx.runQuery(internal.rocketAccounts.listAll, {});

    if (accounts.length === 0) {
      throw new Error("No Rocket.net accounts found. Add API credentials in Server Management.");
    }

    let totalSynced = 0;
    let totalScanned = 0;
    let totalErrors = 0;

    for (const account of accounts) {
      if (!account.apiToken) continue;
      try {
        const result = await doFullSync(ctx, account.apiToken, account._id as string);
        totalSynced += result.sitesSynced;
        totalScanned += result.sitesScanned;
        totalErrors += result.errors;
      } catch (e) {
        totalErrors++;
        const errMsg = e instanceof Error ? e.message : String(e);
        const status = errMsg.includes("expired") || errMsg.includes("invalid") ? "expired" : "error";
        await ctx.runMutation(internal.rocketAccounts.updateAfterSync, {
          id: account._id,
          siteCount: account.siteCount ?? 0,
          status: status as any,
          lastError: errMsg,
        });
      }
    }

    // PHP version is not in Rocket's site list — it needs one settings call
    // per site, so the sweep runs as a background job after the main sync.
    await ctx.scheduler.runAfter(0, internal.phpVersions.syncBatch, { offset: 0 });

    return { sitesSynced: totalSynced, sitesScanned: totalScanned, errors: totalErrors };
  },
});

async function doFullSync(
  ctx: {
    runMutation: (ref: any, args: any) => Promise<any>;
    runQuery: (ref: any, args: any) => Promise<any>;
  },
  token: string,
  accountId: string,
) {
  let sitesSynced = 0;
  let sitesScanned = 0;
  let errors = 0;
  const errorSites: string[] = [];

  try {
    await setProgress(ctx, {
      status: "syncing",
      phase: "Fetching sites list…",
      total: 0,
      completed: 0,
      errors: 0,
    });

    const allSites = await fetchAllSites(token);

    // We only care about production sites (NOT staging)
    // Filter out staging sites — they have no staging_id themselves but
    // parent sites have a staging.staging_id reference
    const productionSites = allSites.filter((s) => {
      // Production sites have a real domain and aren't staging subdomains
      return !isStagingDomain(s.domain);
    });

    await ctx.runMutation(internal.rocketAccounts.updateAfterSync, {
      id: accountId as any,
      siteCount: productionSites.length,
      status: "connected" as const,
    });

    // Upsert all production sites
    const siteIds: Array<{
      docId: string;
      rocketSiteId: number;
      domain: string;
    }> = [];

    for (const site of productionSites) {
      try {
        const siteId = site.id as number;
        const domain = (site.domain as string) ?? "unknown";
        const docId = await ctx.runMutation(internal.sites.upsert, {
          accountId: accountId as any,
          rocketSiteId: siteId,
          domain,
          rocketUrl: site.rocket_url as string | undefined,
          stagingSiteId: stagingIdOf(site),
        });
        siteIds.push({ docId, rocketSiteId: siteId, domain });
        sitesSynced++;
      } catch (e) {
        errors++;
        console.error("Failed to upsert site:", e);
      }
    }

    // Flag entries missing from Rocket.net (records are never auto-deleted)
    const validIds = siteIds.map((s) => s.rocketSiteId);
    await ctx.runMutation(internal.sites.flagMissingSites, {
      validSiteIds: validIds,
      accountId: accountId as any,
    });

    await ctx.runMutation(internal.actionLogs.add, {
      action: "sync_sites",
      details: `Found ${sitesSynced} production sites`,
      status: "info",
    });

    // Phase 2: Scan security for each site
    const total = siteIds.length;
    for (let i = 0; i < siteIds.length; i++) {
      const { docId, rocketSiteId, domain } = siteIds[i];
      await setProgress(ctx, {
        status: "syncing",
        phase: "Scanning security",
        total,
        completed: i,
        currentSite: domain,
        errors,
        errorSites,
      });

      try {
        await scanSiteSecurity(ctx, token, docId, rocketSiteId, accountId, domain);
        sitesScanned++;
      } catch (e) {
        errors++;
        errorSites.push(domain);
        const errMsg = e instanceof Error ? e.message : String(e);
        console.error(`Failed to scan site ${rocketSiteId} (${domain}):`, errMsg);
        await ctx.runMutation(internal.actionLogs.add, {
          siteId: docId as any,
          action: "scan_error",
          details: `Failed to scan ${domain}: ${errMsg}`,
          status: "error",
        });
      }
    }

    // Done
    await setProgress(ctx, {
      status: "done",
      phase: "Complete",
      total,
      completed: total,
      errors,
      errorSites,
    });

    await ctx.runMutation(internal.actionLogs.add, {
      action: "full_sync",
      details: `Security scan complete: ${sitesSynced} sites found, ${sitesScanned} scanned, ${errors} errors`,
      status: errors > 0 ? "error" : "success",
    });
  } catch (e) {
    const errMsg = e instanceof Error ? e.message : "Sync failed";
    await setProgress(ctx, {
      status: "error",
      phase: errMsg,
      total: 0,
      completed: 0,
      errors: errors + 1,
    });
    throw e;
  }

  return { sitesSynced, sitesScanned, errors };
}

// ─── Batched Scanning ────────────────────────────────────────
// Split sync into two phases: (1) sync sites quickly, (2) scan in batches of 30

const BATCH_SIZE = 30;

/**
 * Phase 1: Sync sites from Rocket.net — no security scanning.
 * Fast enough to complete within 10 min even with 400+ sites.
 */
export const syncSitesOnly = action({
  args: {},
  returns: v.object({ sitesSynced: v.number(), errors: v.number() }),
  handler: async (ctx) => {
    const credResult = await ctx.runAction(
      internal.credentialSync.pullFromServerManagement,
      {},
    );
    if (credResult.error) {
      console.warn("Credential sync warning:", credResult.error);
    }

    const accounts = await ctx.runQuery(internal.rocketAccounts.listAll, {});
    if (accounts.length === 0) {
      throw new Error("No Rocket.net accounts found.");
    }

    let totalSynced = 0;
    let totalErrors = 0;

    for (const account of accounts) {
      if (!account.apiToken) continue;
      try {
        const allSites = await fetchAllSites(account.apiToken);
        const productionSites = allSites.filter(
          (s) => !isStagingDomain(s.domain),
        );

        await ctx.runMutation(internal.rocketAccounts.updateAfterSync, {
          id: account._id as any,
          siteCount: productionSites.length,
          status: "connected" as const,
        });

        for (const site of productionSites) {
          try {
            await ctx.runMutation(internal.sites.upsert, {
              accountId: account._id as any,
              rocketSiteId: site.id as number,
              domain: (site.domain as string) ?? "unknown",
              rocketUrl: site.rocket_url as string | undefined,
              stagingSiteId: stagingIdOf(site),
            });
            totalSynced++;
          } catch {
            totalErrors++;
          }
        }

        const validIds = productionSites.map((s) => s.id as number);
        await ctx.runMutation(internal.sites.flagMissingSites, {
          validSiteIds: validIds,
          accountId: account._id as any,
        });
      } catch (e) {
        totalErrors++;
        const errMsg = e instanceof Error ? e.message : String(e);
        const status =
          errMsg.includes("expired") || errMsg.includes("invalid")
            ? "expired"
            : "error";
        await ctx.runMutation(internal.rocketAccounts.updateAfterSync, {
          id: account._id,
          siteCount: account.siteCount ?? 0,
          status: status as any,
          lastError: errMsg,
        });
      }
    }

    return { sitesSynced: totalSynced, errors: totalErrors };
  },
});

/**
 * Phase 2: Scan a batch of sites. Schedules the next batch automatically.
 * Called via scheduler from the HTTP endpoint.
 */
export const scanBatch = internalAction({
  args: {
    offset: v.number(),
  },
  returns: v.object({
    scanned: v.number(),
    errors: v.number(),
    hasMore: v.boolean(),
  }),
  handler: async (ctx, { offset }): Promise<{ scanned: number; errors: number; hasMore: boolean }> => {
    const accounts: Array<{ _id: string; apiToken?: string; siteCount?: number }> = await ctx.runQuery(internal.rocketAccounts.listAll, {});
    if (accounts.length === 0) return { scanned: 0, errors: 0, hasMore: false };

    // We need the token for API calls
    const account = accounts.find((a: { apiToken?: string }) => a.apiToken);
    if (!account) return { scanned: 0, errors: 0, hasMore: false };

    const allSites = await ctx.runQuery(internal.sites.listAll, {}) as any[];
    const batch = allSites.slice(offset, offset + BATCH_SIZE);

    if (batch.length === 0) {
      // All done
      await setProgress(ctx, {
        status: "done",
        phase: "Complete",
        total: allSites.length,
        completed: allSites.length,
        errors: 0,
      });
      return { scanned: 0, errors: 0, hasMore: false };
    }

    await setProgress(ctx, {
      status: "syncing",
      phase: `Scanning batch ${Math.floor(offset / BATCH_SIZE) + 1}`,
      total: allSites.length,
      completed: offset,
      errors: 0,
    });

    let scanned = 0;
    let errors = 0;

    for (const site of batch) {
      try {
        await scanSiteSecurity(
          ctx,
          account.apiToken!,
          site._id as string,
          site.rocketSiteId,
          site.accountId as string,
          site.domain,
        );
        scanned++;
      } catch (e) {
        errors++;
        const errMsg = e instanceof Error ? e.message : String(e);
        console.error(`Scan error ${site.domain}:`, errMsg);
      }
    }

    const hasMore = offset + BATCH_SIZE < allSites.length;

    if (hasMore) {
      // Schedule the next batch
      await ctx.scheduler.runAfter(500, internal.sync.scanBatch, {
        offset: offset + BATCH_SIZE,
      });
    } else {
      await setProgress(ctx, {
        status: "done",
        phase: "Complete",
        total: allSites.length,
        completed: allSites.length,
        errors,
      });
      await ctx.runMutation(internal.actionLogs.add, {
        action: "batched_scan",
        details: `Batched scan complete: ${offset + scanned} sites scanned total`,
        status: errors > 0 ? "error" : "success",
      });
    }

    return { scanned, errors, hasMore };
  },
});
