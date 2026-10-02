/**
 * WordPress core version helpers (plain functions, tested directly); used by
 * sync.ts (production, read-only) and stagingFix.ts (staging).
 *
 * Rocket.net has no core-version field or core-update endpoint (checked
 * 2026-10-02: GET /sites/{id}, /settings and /wp/status carry none, and the
 * site's links list no core rel). Versions come from:
 *  - GET /sites/{id}/files/view?filename=/wp-includes/version.php
 *    (read-only; result.content is the PHP source), and
 *  - WP-CLI on staging: `core version`, `core check-update --format=json`.
 */
import { compareVersions } from "./vulnScan";

const VERSION_RE = /^\d+(\.\d+)*(-[A-Za-z0-9.]+)?$/;

/** $wp_version from the source of wp-includes/version.php. */
export function parseVersionPhp(content: unknown): string | undefined {
  if (typeof content !== "string") return undefined;
  const m = content.match(/^\s*\$wp_version\s*=\s*['"]([^'"]+)['"]\s*;/m);
  return m && VERSION_RE.test(m[1]) ? m[1] : undefined;
}

/** The version `wp core version` printed (last version-looking line, so
 *  PHP warnings before it are ignored). */
export function parseCoreVersion(out: string): string | undefined {
  const lines = out
    .split("\n")
    .map(l => l.trim())
    .reverse();
  return lines.find(l => VERSION_RE.test(l));
}

export type CoreCheck =
  | { kind: "update"; version: string; updateType?: string }
  | { kind: "latest" }
  | { kind: "error"; output: string };

/**
 * Parse `wp core check-update --format=json`. It prints a JSON array of
 * offers ([{"version","update_type","package_url"}], seen 2026-10-02 on
 * staging 282768: 7.0.6 → [{"version":"7.1.2","update_type":"major"}]) or
 * "Success: WordPress is at the latest version." when there is none.
 * `wp core update` (no args) installs the newest offer, so that's returned.
 */
export function parseCheckUpdate(out: string): CoreCheck {
  const lines = out.split("\n").map(l => l.trim());
  for (const l of [...lines].reverse()) {
    if (!l.startsWith("[")) continue;
    try {
      const rows = JSON.parse(l) as {
        version?: unknown;
        update_type?: unknown;
      }[];
      if (!Array.isArray(rows)) continue;
      const offers = rows.filter(
        (r): r is { version: string; update_type?: unknown } =>
          typeof r?.version === "string" && VERSION_RE.test(r.version),
      );
      if (offers.length === 0) return { kind: "latest" };
      const best = offers.reduce((a, b) =>
        compareVersions(b.version, a.version) > 0 ? b : a,
      );
      return {
        kind: "update",
        version: best.version,
        updateType:
          typeof best.update_type === "string" ? best.update_type : undefined,
      };
    } catch {}
  }
  if (/latest version|up to date/i.test(out) && !/fatal error/i.test(out))
    return { kind: "latest" };
  return { kind: "error", output: out.trim() };
}

export type CoreUpdateOutcome = "success" | "already" | "error" | "unclear";

/** Classify `wp core update` / `wp core update-db` output. */
export function classifyCoreOutput(out: string): CoreUpdateOutcome {
  if (/fatal error|^Error:/im.test(out)) return "error";
  if (/latest version|up to date|already at latest/i.test(out))
    return "already";
  if (/^Success:/im.test(out)) return "success";
  return "unclear";
}

/** "major" when the first two version parts differ (WordPress's own
 *  meaning: 7.0 → 7.1 is a major release). */
export function isMajorCoreUpdate(from: string, to: string): boolean {
  const [a1, a2] = from.split(".");
  const [b1, b2] = to.split(".");
  return a1 !== b1 || (a2 ?? "0") !== (b2 ?? "0");
}
