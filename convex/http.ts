import { httpRouter } from "convex/server";
import { httpAction } from "./_generated/server";
import { api, internal } from "./_generated/api";
import { auth } from "./auth";

declare const process: { env: Record<string, string | undefined> };

const http = httpRouter();
auth.addHttpRoutes(http);

// ── Admin sync endpoint ─────────────────────────────────────
// POST /api/admin/sync — stores config and triggers full credential + site sync
http.route({
  path: "/api/admin/sync",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      const body = await request.json();
      const { serverManagementUrl, ssoSharedSecret, adminKey } = body;

      const secret = process.env.SSO_SHARED_SECRET || "66mTA4FYT1TTYfuD6FC7eDHLN15vZC7T3L6DLz3tqbk";
      if (!adminKey || adminKey !== secret) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }

      await ctx.runMutation(internal.credentialSync.upsertConfig, {
        serverManagementUrl,
        ssoSharedSecret,
      });

      // Pull credentials first
      const credResult = await ctx.runAction(internal.credentialSync.pullFromServerManagement, {});

      return new Response(JSON.stringify({ status: "ok", ...credResult }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return new Response(JSON.stringify({ error: msg }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }),
});

http.route({
  path: "/api/admin/sync",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }),
});

// ── Admin endpoint: trigger full security scan ──────────────
http.route({
  path: "/api/admin/full-scan",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      const body = await request.json();
      const secret = process.env.SSO_SHARED_SECRET || "66mTA4FYT1TTYfuD6FC7eDHLN15vZC7T3L6DLz3tqbk";
      if (!body.adminKey || body.adminKey !== secret) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Phase 1: Sync sites only (fast — no security scanning)
      const syncResult = await ctx.runAction(api.sync.syncSitesOnly, {});

      // Phase 2: Start batched security scanning (runs in background)
      await ctx.scheduler.runAfter(1000, internal.sync.scanBatch, { offset: 0 });

      return new Response(JSON.stringify({
        status: "ok",
        sitesSynced: syncResult.sitesSynced,
        syncErrors: syncResult.errors,
        message: "Sites synced. Security scanning started in batches of 30.",
      }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return new Response(JSON.stringify({ error: msg }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }),
});

http.route({
  path: "/api/admin/full-scan",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }),
});

// ── Admin endpoint: trigger vulnerability scan ──────────────
http.route({
  path: "/api/admin/vuln-scan",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      const body = await request.json();
      const secret = process.env.SSO_SHARED_SECRET || "66mTA4FYT1TTYfuD6FC7eDHLN15vZC7T3L6DLz3tqbk";
      if (!body.adminKey || body.adminKey !== secret) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }

      const result = await ctx.runAction(api.vulnScan.scanAllSites, {});

      // Notify Slack about new vulnerabilities if any
      if (result.newVulns > 0) {
        await ctx.scheduler.runAfter(0, internal.vulnScan.notifySlack, {});
      }

      return new Response(JSON.stringify({ status: "ok", ...result }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return new Response(JSON.stringify({ error: msg }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }),
});

http.route({
  path: "/api/admin/vuln-scan",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }),
});

// ── Admin endpoint: re-send vulnerability notifications ─────
http.route({
  path: "/api/admin/vuln-notify",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    try {
      const body = await request.json();
      const secret = process.env.SSO_SHARED_SECRET || "66mTA4FYT1TTYfuD6FC7eDHLN15vZC7T3L6DLz3tqbk";
      if (!body.adminKey || body.adminKey !== secret) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        });
      }

      // Reset all slackNotified flags
      const resetResult = await ctx.runMutation(internal.vulnerabilities.resetAllNotified, {});

      // Trigger notification
      await ctx.scheduler.runAfter(0, internal.vulnScan.notifySlack, {});

      return new Response(JSON.stringify({ status: "ok", ...resetResult }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return new Response(JSON.stringify({ error: msg }), {
        status: 500,
        headers: { "Content-Type": "application/json" },
      });
    }
  }),
});

http.route({
  path: "/api/admin/vuln-notify",
  method: "OPTIONS",
  handler: httpAction(async () => {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type",
      },
    });
  }),
});

http.route({
  path: "/api/admin/recalc-scores",
  method: "POST",
  handler: httpAction(async (ctx, request) => {
    const secret = process.env.SSO_SHARED_SECRET || "66mTA4FYT1TTYfuD6FC7eDHLN15vZC7T3L6DLz3tqbk";
    if (request.headers.get("Authorization") !== `Bearer ${secret}`) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), { status: 403, headers: { "Content-Type": "application/json" } });
    }
    const result = await ctx.runMutation(internal.securityScore.recalcAll, {});
    return new Response(JSON.stringify({ status: "ok", ...result }), { status: 200, headers: { "Content-Type": "application/json" } });
  }),
});

export default http;
