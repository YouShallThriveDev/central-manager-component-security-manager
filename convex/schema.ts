import { authTables } from "@convex-dev/auth/server";
import { defineSchema, defineTable } from "convex/server";
import { v } from "convex/values";

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
    phpVersion: v.optional(v.string()),
    phpCheckedAt: v.optional(v.number()),
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
