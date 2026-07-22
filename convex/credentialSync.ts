/**
 * Credential sync — pulls API credentials from the central Server Management
 * component and mirrors them into the local rocketAccounts table.
 *
 * This replaces manual token entry. Accounts are now managed centrally in
 * Server Management; this component just reads from it.
 */
import { internalAction, internalMutation, internalQuery } from "./_generated/server";
import { internal } from "./_generated/api";
import { v } from "convex/values";

declare const process: { env: Record<string, string | undefined> };

interface Credential {
  id: string;
  provider: string;
  label: string;
  apiToken: string;
  apiUrl?: string;
  username?: string;
  extraConfig?: Record<string, unknown>;
}

/**
 * Fetch all Rocket.net credentials from Server Management and sync them
 * into the local rocketAccounts table.
 */
export const pullFromServerManagement = internalAction({
  args: {},
  returns: v.object({
    synced: v.number(),
    removed: v.number(),
    error: v.optional(v.string()),
  }),
  handler: async (ctx): Promise<{ synced: number; removed: number; error?: string }> => {
    let smUrl = process.env.SERVER_MANAGEMENT_URL;
    let secret = process.env.SSO_SHARED_SECRET;

    // Fallback to settings table if env vars not set
    if (!smUrl || !secret) {
      const config: { serverManagementUrl: string; ssoSharedSecret: string } | null = await ctx.runQuery(internal.credentialSync.getConfig, {});
      if (config) {
        smUrl = smUrl || config.serverManagementUrl;
        secret = secret || config.ssoSharedSecret;
      }
    }

    if (!smUrl || !secret) {
      return { synced: 0, removed: 0, error: "SERVER_MANAGEMENT_URL or SSO_SHARED_SECRET not configured" };
    }

    try {
      // Fetch ALL hosting credentials from Server Management (Rocket.net, Cloudways, etc.)
      const resp = await fetch(`${smUrl}/api/credentials`, {
        headers: { Authorization: `Bearer ${secret}` },
      });

      if (!resp.ok) {
        const text = await resp.text();
        return { synced: 0, removed: 0, error: `Server Management API error (${resp.status}): ${text}` };
      }

      const data = (await resp.json()) as { credentials: Credential[] };
      const remoteCredentials = data.credentials ?? [];

      // Get current local accounts
      const localAccounts = await ctx.runQuery(internal.rocketAccounts.listAll, {});

      // Track which remote labels we've seen
      const remoteLabels = new Set(remoteCredentials.map((c) => c.label));

      // Upsert: update existing or create new local accounts
      let synced = 0;
      for (const cred of remoteCredentials) {
        const existing = localAccounts.find((a: any) => a.label === cred.label);

        if (existing) {
          await ctx.runMutation(internal.credentialSync.patchAccount, {
            id: existing._id,
            label: cred.label,
            apiToken: cred.apiToken,
          });
        } else {
          await ctx.runMutation(internal.credentialSync.insertAccount, {
            label: cred.label,
            apiToken: cred.apiToken,
          });
        }
        synced++;
      }

      // Remove local accounts that no longer exist in Server Management
      let removed = 0;
      for (const local of localAccounts) {
        if (!remoteLabels.has(local.label)) {
          // Use the existing rocketAccounts.remove to cascade-delete sites etc.
          await ctx.runMutation(internal.credentialSync.cascadeDeleteAccount, {
            id: local._id,
          });
          removed++;
        }
      }

      return { synced, removed };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { synced: 0, removed: 0, error: msg };
    }
  },
});

// ── Internal mutations ──────────────────────────────────────

export const patchAccount = internalMutation({
  args: {
    id: v.id("rocketAccounts"),
    label: v.string(),
    apiToken: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    await ctx.db.patch(args.id, {
      label: args.label,
      apiToken: args.apiToken,
      status: "connected" as const,
      lastError: undefined,
    });
    return null;
  },
});

export const insertAccount = internalMutation({
  args: {
    label: v.string(),
    apiToken: v.string(),
  },
  returns: v.id("rocketAccounts"),
  handler: async (ctx, args) => {
    return await ctx.db.insert("rocketAccounts", {
      label: args.label,
      apiToken: args.apiToken,
      status: "connected" as const,
    });
  },
});

export const cascadeDeleteAccount = internalMutation({
  args: {
    id: v.id("rocketAccounts"),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const sites = await ctx.db
      .query("sites")
      .withIndex("by_account", (q) => q.eq("accountId", args.id))
      .collect();

    for (const site of sites) {
      const plugins = await ctx.db
        .query("sitePlugins")
        .withIndex("by_site", (q) => q.eq("siteId", site._id))
        .collect();
      for (const p of plugins) await ctx.db.delete(p._id);

      const muPlugins = await ctx.db
        .query("siteMuPlugins")
        .withIndex("by_site", (q) => q.eq("siteId", site._id))
        .collect();
      for (const m of muPlugins) await ctx.db.delete(m._id);

      const logs = await ctx.db
        .query("actionLogs")
        .withIndex("by_site", (q) => q.eq("siteId", site._id))
        .collect();
      for (const l of logs) await ctx.db.delete(l._id);

      await ctx.db.delete(site._id);
    }

    await ctx.db.delete(args.id);
    return null;
  },
});

// ── Settings-based config fallback ──────────────────────────

export const getConfig = internalQuery({
  args: {},
  handler: async (ctx) => {
    const urlSetting = await ctx.db
      .query("settings")
      .withIndex("by_key", (q) => q.eq("key", "server_management_url"))
      .first();
    const secretSetting = await ctx.db
      .query("settings")
      .withIndex("by_key", (q) => q.eq("key", "sso_shared_secret"))
      .first();

    if (!urlSetting || !secretSetting) return null;
    return {
      serverManagementUrl: urlSetting.value,
      ssoSharedSecret: secretSetting.value,
    };
  },
});

export const upsertConfig = internalMutation({
  args: {
    serverManagementUrl: v.string(),
    ssoSharedSecret: v.string(),
  },
  returns: v.null(),
  handler: async (ctx, args) => {
    const pairs = [
      { key: "server_management_url", value: args.serverManagementUrl },
      { key: "sso_shared_secret", value: args.ssoSharedSecret },
    ];
    for (const { key, value } of pairs) {
      const existing = await ctx.db
        .query("settings")
        .withIndex("by_key", (q) => q.eq("key", key))
        .first();
      if (existing) {
        await ctx.db.patch(existing._id, { value });
      } else {
        await ctx.db.insert("settings", { key, value });
      }
    }
    return null;
  },
});
