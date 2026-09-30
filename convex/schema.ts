import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

export const stagingFixStatus = v.union(
  v.literal("queued"),
  v.literal("running"),
  v.literal("done"),
  v.literal("failed"),
  v.literal("skipped"),
);

export const stagingFixAction = v.object({
  kind: v.union(v.literal("update_plugin"), v.literal("activate_wordfence")),
  slug: v.string(),
  name: v.optional(v.string()),
  fixedIn: v.optional(v.string()),
  status: v.union(
    v.literal("pending"),
    v.literal("done"),
    v.literal("failed"),
    v.literal("skipped"),
  ),
  fromVersion: v.optional(v.string()),
  toVersion: v.optional(v.string()),
  note: v.optional(v.string()),
});

const schema = defineSchema({
  ...authTables,

  // Rocket.net hosting accounts (supports multiple)
  rocketAccounts: defineTable({
    label: v.string(),
    apiToken: v.string(),
    status: v.union(
      v.literal("connected"),
      v.literal("error"),
      v.literal("expired"),
    ),
    siteCount: v.optional(v.number()),
    lastSyncedAt: v.optional(v.number()),
    lastError: v.optional(v.string()),
  }),

  // Production sites
  sites: defineTable({
    accountId: v.optional(v.id("rocketAccounts")),
    rocketSiteId: v.number(), // Rocket.net site ID
    domain: v.string(),
    rocketUrl: v.optional(v.string()),
    stagingSiteId: v.optional(v.number()), // Rocket.net id of this site's staging copy
    phpVersion: v.optional(v.string()),
    phpCheckedAt: v.optional(v.number()),
    // Rocket.net presence — set by the PHP/settings probe. Records are NEVER
    // auto-deleted; a site missing from Rocket.net is flagged here and shown
    // in the UI so a human decides whether to remove it.
    rocketStatus: v.optional(v.string()), // "ok" | "missing" | "auth_error"
    rocketMissingSince: v.optional(v.number()),
    wpVersion: v.optional(v.string()),
    wpUpdateAvailable: v.optional(v.boolean()),
    sslEnabled: v.optional(v.boolean()),
    lastSyncedAt: v.optional(v.number()),
    // Security summary
    securityScore: v.optional(v.number()), // 0-100
    securityGrade: v.optional(
      v.union(
        v.literal("A"),
        v.literal("B"),
        v.literal("C"),
        v.literal("D"),
        v.literal("F"),
      ),
    ),
    securityBaseScore: v.optional(v.number()),
    vulnPenalty: v.optional(v.number()),
    vulnGradeCap: v.optional(v.string()),
    openVulnCritical: v.optional(v.number()),
    openVulnHigh: v.optional(v.number()),
    openVulnMedium: v.optional(v.number()),
    openVulnLow: v.optional(v.number()),
    activeSecurityPlugins: v.optional(v.number()),
    totalPlugins: v.optional(v.number()),
    pluginsNeedingUpdate: v.optional(v.number()),
    hasFirewall: v.optional(v.boolean()),
    hasMalwareScanner: v.optional(v.boolean()),
    hasBackup: v.optional(v.boolean()),
    hasTwoFactor: v.optional(v.boolean()),
    hasBruteForceProtection: v.optional(v.boolean()),
    // Wordfence specific
    wordfenceInstalled: v.optional(v.boolean()),
    wordfenceActive: v.optional(v.boolean()),
    wordfenceVersion: v.optional(v.string()),
    // Scan results
    lastScanAt: v.optional(v.number()),
    lastScanResult: v.optional(v.string()), // JSON string of scan findings
  })
    .index("by_rocket_site_id", ["rocketSiteId"])
    .index("by_domain", ["domain"])
    .index("by_account", ["accountId"])
    .index("by_security_grade", ["securityGrade"]),

  // All plugins per site
  sitePlugins: defineTable({
    siteId: v.id("sites"),
    slug: v.string(),
    displayName: v.optional(v.string()),
    status: v.union(
      v.literal("active"),
      v.literal("inactive"),
      v.literal("must-use"),
    ),
    version: v.optional(v.string()),
    updateAvailable: v.optional(v.boolean()),
    isSecurityPlugin: v.boolean(),
    securityCategory: v.optional(
      v.union(
        v.literal("firewall"),
        v.literal("malware"),
        v.literal("brute-force"),
        v.literal("two-factor"),
        v.literal("backup"),
        v.literal("general-security"),
        v.literal("monitoring"),
      ),
    ),
  })
    .index("by_site", ["siteId"])
    .index("by_site_and_slug", ["siteId", "slug"]),

  // MU-plugins per site
  siteMuPlugins: defineTable({
    siteId: v.id("sites"),
    filename: v.string(),
    present: v.boolean(),
    isSecurityRelated: v.boolean(),
  })
    .index("by_site", ["siteId"])
    .index("by_site_and_filename", ["siteId", "filename"]),

  // Vulnerability alerts per site+plugin
  vulnerabilities: defineTable({
    siteId: v.id("sites"),
    pluginSlug: v.string(),
    pluginVersion: v.optional(v.string()),
    cveId: v.optional(v.string()), // e.g. CVE-2026-12345
    title: v.string(),
    severity: v.union(
      v.literal("critical"),
      v.literal("high"),
      v.literal("medium"),
      v.literal("low"),
    ),
    cvssScore: v.optional(v.number()), // 0-10
    description: v.optional(v.string()),
    fixedInVersion: v.optional(v.string()),
    source: v.string(), // "wordfence" | "wpscan" | "patchstack"
    sourceUrl: v.optional(v.string()),
    status: v.union(
      v.literal("open"),
      v.literal("patched"),
      v.literal("dismissed"),
    ),
    firstDetectedAt: v.number(),
    resolvedAt: v.optional(v.number()),
    slackNotified: v.boolean(),
  })
    .index("by_site", ["siteId"])
    .index("by_site_plugin", ["siteId", "pluginSlug"])
    .index("by_status", ["status"])
    .index("by_severity", ["severity"]),

  // App settings
  settings: defineTable({
    key: v.string(),
    value: v.string(),
  }).index("by_key", ["key"]),

  // Bulk "fix on staging" runs. Writes only ever target staging copies.
  stagingFixJobs: defineTable({
    status: v.union(v.literal("running"), v.literal("done")),
    total: v.number(),
    startedBy: v.optional(v.string()),
    finishedAt: v.optional(v.number()),
  }),

  stagingFixItems: defineTable({
    jobId: v.id("stagingFixJobs"),
    siteId: v.id("sites"),
    domain: v.string(),
    stagingSiteId: v.optional(v.number()),
    status: stagingFixStatus,
    error: v.optional(v.string()),
    actions: v.array(stagingFixAction),
    startedAt: v.optional(v.number()),
    finishedAt: v.optional(v.number()),
  })
    .index("by_job", ["jobId"])
    .index("by_job_and_status", ["jobId", "status"]),

  // Action log for audit trail
  actionLogs: defineTable({
    siteId: v.optional(v.id("sites")),
    action: v.string(),
    details: v.string(),
    status: v.union(
      v.literal("success"),
      v.literal("error"),
      v.literal("info"),
    ),
  }).index("by_site", ["siteId"]),
});

export default schema;
