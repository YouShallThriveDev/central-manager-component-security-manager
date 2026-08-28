import { Badge } from "@/components/ui/badge";

export type RocketStatus = "ok" | "missing" | "auth_error";

/**
 * Rocket.net presence for a site record.
 *
 * Records are never deleted automatically. When Rocket.net stops returning a
 * site, the record is flagged here so it stays visible until a person removes
 * it deliberately.
 */
export function rocketStatusOf(status?: string): RocketStatus {
  if (status === "missing" || status === "auth_error") return status;
  return "ok";
}

const statusClass: Record<RocketStatus, string> = {
  ok: "",
  missing:
    "border-red-300 text-red-700 bg-red-50 dark:bg-red-950/30 dark:text-red-400",
  auth_error:
    "border-amber-300 text-amber-700 bg-amber-50 dark:bg-amber-950/30 dark:text-amber-400",
};

const statusLabel: Record<RocketStatus, string> = {
  ok: "On Rocket.net",
  missing: "Missing from Rocket.net",
  auth_error: "Rocket.net read failed",
};

const statusTitle: Record<RocketStatus, string> = {
  ok: "Site responds on Rocket.net",
  missing:
    "Rocket.net no longer returns this site. The record is kept until someone removes it.",
  auth_error:
    "Rocket.net rejected the read (token or permission problem) — not necessarily a deleted site.",
};

/** Renders nothing for healthy sites so lists stay quiet. */
export function RocketStatusBadge({
  status,
  missingSince,
  className,
}: {
  status?: string;
  missingSince?: number;
  className?: string;
}) {
  const tier = rocketStatusOf(status);
  if (tier === "ok") return null;

  const title =
    tier === "missing" && missingSince
      ? `${statusTitle[tier]} First seen missing ${new Date(missingSince).toLocaleDateString()}.`
      : statusTitle[tier];

  return (
    <Badge
      variant="outline"
      title={title}
      className={`text-xs ${statusClass[tier]} ${className ?? ""}`}
    >
      {statusLabel[tier]}
    </Badge>
  );
}

/** Standard Rocket.net status filter options — identical across suite apps. */
export const ROCKET_FILTER_OPTIONS: { value: string; label: string }[] = [
  { value: "ok", label: "On Rocket.net" },
  { value: "missing", label: "Missing from Rocket.net" },
  { value: "auth_error", label: "Rocket.net read failed" },
];

export const ROCKET_FILTER_ALL_LABEL = "All Rocket.net statuses";

export function matchesRocketFilter(status: string | undefined, filter: string): boolean {
  if (filter === "all") return true;
  return rocketStatusOf(status) === filter;
}
