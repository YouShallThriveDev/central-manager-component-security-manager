import { Badge } from "@/components/ui/badge";

export type PhpTier = "ok" | "warning" | "critical" | "unknown";

/** 8.1+ is supported, 8.0 is past EOL but modern, anything below is critical. */
export function phpTier(version?: string): PhpTier {
  if (!version) return "unknown";
  const num = parseFloat(version);
  if (Number.isNaN(num)) return "unknown";
  if (num >= 8.1) return "ok";
  if (num >= 8.0) return "warning";
  return "critical";
}

/** Sort key so 8.10 > 8.9 and unknown sinks to the bottom. */
export function phpSortValue(version?: string): number {
  if (!version) return -1;
  const parts = version.split(".").map((p) => parseInt(p, 10));
  const major = Number.isNaN(parts[0]) ? 0 : parts[0];
  const minor = Number.isNaN(parts[1]) ? 0 : parts[1];
  return major * 100 + minor;
}

const tierClass: Record<PhpTier, string> = {
  ok: "border-emerald-300 text-emerald-700 bg-emerald-50 dark:bg-emerald-950/30 dark:text-emerald-400",
  warning: "border-amber-300 text-amber-700 bg-amber-50 dark:bg-amber-950/30 dark:text-amber-400",
  critical: "border-red-300 text-red-700 bg-red-50 dark:bg-red-950/30 dark:text-red-400",
  unknown: "border-border text-muted-foreground bg-muted/40",
};

const tierTitle: Record<PhpTier, string> = {
  ok: "Supported PHP version",
  warning: "PHP 8.0 is past end-of-life — plan an upgrade",
  critical: "End-of-life PHP — security risk, upgrade needed",
  unknown: "PHP version not synced yet",
};

export function PhpVersionBadge({
  version,
  checkedAt,
  className,
}: {
  version?: string;
  checkedAt?: number;
  className?: string;
}) {
  const tier = phpTier(version);
  const title = checkedAt
    ? `${tierTitle[tier]} · checked ${new Date(checkedAt).toLocaleString()}`
    : tierTitle[tier];

  return (
    <Badge
      variant="outline"
      title={title}
      className={`text-xs tabular-nums ${tierClass[tier]} ${className ?? ""}`}
    >
      {version ? `PHP ${version}` : "PHP —"}
    </Badge>
  );
}

/** Standard PHP filter dropdown options — keep identical across all suite apps. */
export const PHP_FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: "ok", label: "PHP 8.1+" },
  { value: "warning", label: "PHP 8.0" },
  { value: "critical", label: "PHP 7.4 and older" },
  { value: "unknown", label: "Not synced" },
];

export const PHP_FILTER_ALL_LABEL = "All PHP versions";

/** True when a site's PHP version passes the selected filter value. */
export function matchesPhpFilter(version: string | undefined, filter: string): boolean {
  if (filter === "all") return true;
  return phpTier(version) === filter;
}
