import { useQuery, useAction, useMutation } from "convex/react";
import { api } from "../../convex/_generated/api";
import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  AlertTriangle,
  ShieldAlert,
  ShieldX,
  ShieldOff,
  Shield,
  RefreshCw,
  Loader2,
  CheckCircle2,
  ExternalLink,
  Bug,
  AlertCircle,
  Info,
  XCircle,
  RotateCcw,
  ArrowUpCircle,
  RotateCw,
} from "lucide-react";
import { toast } from "sonner";

type Severity = "critical" | "high" | "medium" | "low";

const severityConfig: Record<
  Severity,
  { color: string; bgColor: string; borderColor: string; icon: typeof ShieldAlert; label: string }
> = {
  critical: {
    color: "text-red-700 dark:text-red-400",
    bgColor: "bg-red-50 dark:bg-red-950/30",
    borderColor: "border-red-300",
    icon: ShieldOff,
    label: "Critical",
  },
  high: {
    color: "text-orange-700 dark:text-orange-400",
    bgColor: "bg-orange-50 dark:bg-orange-950/30",
    borderColor: "border-orange-300",
    icon: ShieldX,
    label: "High",
  },
  medium: {
    color: "text-amber-700 dark:text-amber-400",
    bgColor: "bg-amber-50 dark:bg-amber-950/30",
    borderColor: "border-amber-300",
    icon: ShieldAlert,
    label: "Medium",
  },
  low: {
    color: "text-blue-700 dark:text-blue-400",
    bgColor: "bg-blue-50 dark:bg-blue-950/30",
    borderColor: "border-blue-300",
    icon: Shield,
    label: "Low",
  },
};

function SeverityBadge({ severity }: { severity: Severity }) {
  const c = severityConfig[severity];
  const Icon = c.icon;
  return (
    <Badge
      variant="outline"
      className={`gap-1 text-xs font-bold ${c.color} ${c.bgColor} ${c.borderColor}`}
    >
      <Icon className="size-3" />
      {c.label}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  if (status === "open") {
    return (
      <Badge
        variant="outline"
        className="gap-1 text-xs border-red-300 text-red-600 bg-red-50 dark:bg-red-950/30"
      >
        <AlertCircle className="size-3" />
        Open
      </Badge>
    );
  }
  if (status === "patched") {
    return (
      <Badge
        variant="outline"
        className="gap-1 text-xs border-emerald-300 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30"
      >
        <CheckCircle2 className="size-3" />
        Patched
      </Badge>
    );
  }
  return (
    <Badge variant="outline" className="gap-1 text-xs">
      <Info className="size-3" />
      Dismissed
    </Badge>
  );
}

export default function VulnerabilitiesPage() {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("open");

  const navigate = useNavigate();
  const vulnStats = useQuery(api.vulnerabilities.stats);
  const queryStatus = statusFilter === "update_available" ? "open" : statusFilter;
  const rawVulns = useQuery(api.vulnerabilities.list, {
    severity: severityFilter === "all" ? undefined : severityFilter,
    status: queryStatus === "all" ? undefined : queryStatus,
  });
  // Client-side filter for "update available" (open + has fixedInVersion)
  const vulns = rawVulns && statusFilter === "update_available"
    ? rawVulns.filter((v) => v.fixedInVersion)
    : rawVulns;
  const sites = useQuery(api.sites.list, {});
  const scanAllSites = useAction(api.vulnScan.scanAllSites);
  const rescanSite = useAction(api.vulnScan.rescanSite);
  const dismissVuln = useMutation(api.vulnerabilities.dismissVuln);
  const reopenVuln = useMutation(api.vulnerabilities.reopenVuln);
  const vulnScanProgress = useQuery(api.settings.getVulnScanProgress);
  const [recheckingSiteId, setRecheckingSiteId] = useState<string | null>(null);

  const isScanningVulns =
    vulnScanProgress?.status === "scanning";
  const isDone = vulnScanProgress?.status === "done";

  useEffect(() => {
    if (isDone && vulnScanProgress) {
      const t = setTimeout(() => {
        toast.success(
          `Scan complete: ${vulnScanProgress.vulnsFound ?? 0} vulnerabilities found (${vulnScanProgress.newVulns ?? 0} new)`,
        );
      }, 500);
      return () => clearTimeout(t);
    }
  }, [isDone]);

  const [scanning, setScanning] = useState(false);

  const handleRescan = useCallback(async (siteId: string, domain: string) => {
    setRecheckingSiteId(siteId);
    toast.info(`Rechecking ${domain}…`);
    try {
      const result = await rescanSite({ siteId: siteId as any });
      if (result.resolved > 0) {
        toast.success(
          `${domain}: ${result.resolved} vulnerabilit${result.resolved !== 1 ? "ies" : "y"} resolved! ${result.pluginsChecked} plugins checked.`,
        );
      } else {
        toast.info(
          `${domain}: ${result.pluginsChecked} plugins checked, ${result.vulnsFound} vulnerabilities found (${result.newVulns} new). No changes in status.`,
        );
      }
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Recheck failed");
    } finally {
      setRecheckingSiteId(null);
    }
  }, [rescanSite]);

  const handleScan = useCallback(async () => {
    setScanning(true);
    toast.info("Vulnerability scan started…");
    try {
      const result = await scanAllSites({});
      toast.success(
        `Found ${result.vulnsFound} vulnerabilities (${result.newVulns} new) across ${result.sitesScanned} sites`,
      );
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Scan failed");
    } finally {
      setScanning(false);
    }
  }, [scanAllSites]);

  // Build domain lookup
  const siteDomains: Record<string, string> = {};
  if (sites) {
    for (const s of sites) {
      siteDomains[s._id] = s.domain;
    }
  }

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            Vulnerability Alerts
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Known plugin/theme vulnerabilities across all sites
          </p>
        </div>
        <Button
          onClick={handleScan}
          disabled={scanning || isScanningVulns}
          variant="outline"
          className="gap-2"
        >
          {scanning || isScanningVulns ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <RefreshCw className="size-4" />
          )}
          {scanning || isScanningVulns
            ? "Scanning..."
            : "Scan for Vulnerabilities"}
        </Button>
      </div>

      {/* Scan Progress */}
      {(isScanningVulns || isDone) && vulnScanProgress && (
        <div className="rounded-lg border bg-card p-4 space-y-3 animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {isScanningVulns ? (
                <Loader2 className="size-4 animate-spin text-amber-500" />
              ) : (
                <CheckCircle2 className="size-4 text-emerald-600" />
              )}
              <span className="text-sm font-medium">
                {vulnScanProgress.phase}
              </span>
            </div>
            <span className="text-sm tabular-nums text-muted-foreground">
              {vulnScanProgress.total > 0
                ? `${vulnScanProgress.completed} / ${vulnScanProgress.total} plugins`
                : ""}
            </span>
          </div>
          <Progress
            value={
              vulnScanProgress.total > 0
                ? (vulnScanProgress.completed / vulnScanProgress.total) * 100
                : isScanningVulns
                  ? 5
                  : 0
            }
            className="h-2"
          />
        </div>
      )}

      {/* Stats Row */}
      {vulnStats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-red-100 dark:bg-red-900/20">
                <Bug className="size-4 text-red-600" />
              </div>
              <div>
                <p className="text-2xl font-bold tabular-nums">
                  {vulnStats.open}
                </p>
                <p className="text-xs text-muted-foreground">Open</p>
              </div>
            </div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-red-100 dark:bg-red-900/20">
                <ShieldOff className="size-4 text-red-700" />
              </div>
              <div>
                <p className="text-2xl font-bold tabular-nums text-red-700 dark:text-red-400">
                  {vulnStats.critical}
                </p>
                <p className="text-xs text-muted-foreground">Critical</p>
              </div>
            </div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-orange-100 dark:bg-orange-900/20">
                <ShieldX className="size-4 text-orange-600" />
              </div>
              <div>
                <p className="text-2xl font-bold tabular-nums text-orange-700 dark:text-orange-400">
                  {vulnStats.high}
                </p>
                <p className="text-xs text-muted-foreground">High</p>
              </div>
            </div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-amber-100 dark:bg-amber-900/20">
                <ShieldAlert className="size-4 text-amber-600" />
              </div>
              <div>
                <p className="text-2xl font-bold tabular-nums">
                  {vulnStats.medium + vulnStats.low}
                </p>
                <p className="text-xs text-muted-foreground">Medium/Low</p>
              </div>
            </div>
          </div>
          <div
            className={`rounded-lg border bg-card p-4 cursor-pointer transition-colors ${statusFilter === "update_available" ? "ring-2 ring-blue-500" : "hover:bg-muted/50"}`}
            onClick={() => setStatusFilter(statusFilter === "update_available" ? "open" : "update_available")}
          >
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-blue-100 dark:bg-blue-900/20">
                <ArrowUpCircle className="size-4 text-blue-600" />
              </div>
              <div>
                <p className="text-2xl font-bold tabular-nums text-blue-700 dark:text-blue-400">
                  {vulnStats.updateAvailable}
                </p>
                <p className="text-xs text-muted-foreground">Update Available</p>
              </div>
            </div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-emerald-100 dark:bg-emerald-900/20">
                <CheckCircle2 className="size-4 text-emerald-600" />
              </div>
              <div>
                <p className="text-2xl font-bold tabular-nums">
                  {vulnStats.patched}
                </p>
                <p className="text-xs text-muted-foreground">Patched</p>
              </div>
            </div>
          </div>
          <div className="rounded-lg border bg-card p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-md bg-muted">
                <AlertTriangle className="size-4 text-muted-foreground" />
              </div>
              <div>
                <p className="text-2xl font-bold tabular-nums">
                  {vulnStats.affectedSites}
                </p>
                <p className="text-xs text-muted-foreground">Sites Affected</p>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All statuses</SelectItem>
            <SelectItem value="open">Open</SelectItem>
            <SelectItem value="update_available">Update Available</SelectItem>
            <SelectItem value="patched">Patched</SelectItem>
            <SelectItem value="dismissed">Dismissed</SelectItem>
          </SelectContent>
        </Select>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-[140px]">
            <SelectValue placeholder="Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All severities</SelectItem>
            <SelectItem value="critical">Critical</SelectItem>
            <SelectItem value="high">High</SelectItem>
            <SelectItem value="medium">Medium</SelectItem>
            <SelectItem value="low">Low</SelectItem>
          </SelectContent>
        </Select>
        {vulns && (
          <span className="text-sm text-muted-foreground tabular-nums">
            {vulns.length} vulnerabilit{vulns.length !== 1 ? "ies" : "y"}
          </span>
        )}
      </div>

      {/* Vulnerabilities Table */}
      <div className="rounded-lg border bg-card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Vulnerability
              </th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Site
              </th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Plugin
              </th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Severity
              </th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                CVSS
              </th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Fix
              </th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Status
              </th>
              <th className="py-2.5 px-4 w-10" />
            </tr>
          </thead>
          <tbody>
            {vulns === undefined ? (
              <tr>
                <td
                  colSpan={8}
                  className="py-12 text-center text-muted-foreground"
                >
                  Loading...
                </td>
              </tr>
            ) : vulns.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center">
                  <div className="flex flex-col items-center gap-2">
                    <Shield className="size-8 text-muted-foreground/50" />
                    <p className="text-sm text-muted-foreground">
                      {vulnStats && vulnStats.total === 0
                        ? 'No vulnerabilities found yet. Click "Scan for Vulnerabilities" to check.'
                        : "No vulnerabilities match your filters"}
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              vulns.map((vuln) => (
                <tr
                  key={vuln._id}
                  className="border-b border-border/50 hover:bg-muted/50 transition-colors"
                >
                  <td className="py-3 px-4 max-w-[300px]">
                    <div className="flex flex-col gap-0.5">
                      <span className="font-medium text-sm truncate">
                        {vuln.title}
                      </span>
                      {vuln.cveId && (
                        <span className="text-xs text-muted-foreground font-mono">
                          {vuln.cveId}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <button
                      onClick={() => navigate(`/site/${vuln.siteId}`)}
                      className="text-sm text-primary hover:underline"
                    >
                      {siteDomains[vuln.siteId] || "Unknown"}
                    </button>
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-sm">{vuln.pluginSlug}</span>
                      {vuln.pluginVersion && (
                        <span className="text-xs text-muted-foreground tabular-nums">
                          v{vuln.pluginVersion}
                        </span>
                      )}
                    </div>
                  </td>
                  <td className="py-3 px-4">
                    <SeverityBadge severity={vuln.severity} />
                  </td>
                  <td className="py-3 px-4">
                    {vuln.cvssScore !== undefined ? (
                      <span
                        className={`text-sm font-bold tabular-nums ${
                          vuln.cvssScore >= 9.0
                            ? "text-red-700 dark:text-red-400"
                            : vuln.cvssScore >= 7.0
                              ? "text-orange-700 dark:text-orange-400"
                              : vuln.cvssScore >= 4.0
                                ? "text-amber-700 dark:text-amber-400"
                                : "text-blue-700 dark:text-blue-400"
                        }`}
                      >
                        {vuln.cvssScore.toFixed(1)}
                      </span>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    {vuln.fixedInVersion ? (
                      <Badge
                        variant="outline"
                        className="text-xs border-emerald-300 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30"
                      >
                        → v{vuln.fixedInVersion}
                      </Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">
                        No fix yet
                      </span>
                    )}
                  </td>
                  <td className="py-3 px-4">
                    <StatusBadge status={vuln.status} />
                  </td>
                  <td className="py-3 px-4">
                    <div className="flex items-center gap-2">
                      <button
                        onClick={async (e) => {
                          e.stopPropagation();
                          handleRescan(
                            vuln.siteId,
                            siteDomains[vuln.siteId] || "site",
                          );
                        }}
                        disabled={recheckingSiteId === vuln.siteId}
                        className="text-muted-foreground hover:text-blue-600 disabled:opacity-40"
                        title="Recheck this site"
                      >
                        {recheckingSiteId === vuln.siteId ? (
                          <Loader2 className="size-3.5 animate-spin" />
                        ) : (
                          <RotateCw className="size-3.5" />
                        )}
                      </button>
                      {vuln.sourceUrl && (
                        <a
                          href={vuln.sourceUrl}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-muted-foreground hover:text-foreground"
                          title="View details"
                        >
                          <ExternalLink className="size-3.5" />
                        </a>
                      )}
                      {vuln.status === "open" ? (
                        <button
                          onClick={async (e) => {
                            e.stopPropagation();
                            try {
                              await dismissVuln({ id: vuln._id });
                              toast.success("Vulnerability dismissed");
                            } catch {
                              toast.error("Failed to dismiss");
                            }
                          }}
                          className="text-muted-foreground hover:text-foreground"
                          title="Dismiss vulnerability"
                        >
                          <XCircle className="size-3.5" />
                        </button>
                      ) : (
                        <button
                          onClick={async (e) => {
                            e.stopPropagation();
                            try {
                              await reopenVuln({ id: vuln._id });
                              toast.success("Vulnerability reopened");
                            } catch {
                              toast.error("Failed to reopen");
                            }
                          }}
                          className="text-muted-foreground hover:text-foreground"
                          title="Reopen vulnerability"
                        >
                          <RotateCcw className="size-3.5" />
                        </button>
                      )}
                    </div>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
