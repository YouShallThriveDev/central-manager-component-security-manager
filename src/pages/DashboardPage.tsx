import { useQuery, useAction } from "convex/react";
import { api } from "../../convex/_generated/api";
import { useState, useCallback, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  RefreshCw,
  Search,
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  ShieldOff,
  AlertTriangle,
  CheckCircle2,
  Server,
  ExternalLink,
  Loader2,
  Flame,
  Bug,
  HardDrive,
  KeyRound,
  Lock,
  Cpu,
} from "lucide-react";
import { toast } from "sonner";
import type { Doc } from "../../convex/_generated/dataModel";
import { PhpVersionBadge, phpSortValue, matchesPhpFilter, PHP_FILTER_OPTIONS, PHP_FILTER_ALL_LABEL } from "@/components/PhpVersionBadge";

type GradeType = "A" | "B" | "C" | "D" | "F";

const gradeConfig: Record<GradeType, { color: string; bgColor: string; borderColor: string; icon: typeof ShieldCheck }> = {
  A: { color: "text-emerald-700", bgColor: "bg-emerald-50 dark:bg-emerald-950/30", borderColor: "border-emerald-300", icon: ShieldCheck },
  B: { color: "text-blue-700", bgColor: "bg-blue-50 dark:bg-blue-950/30", borderColor: "border-blue-300", icon: Shield },
  C: { color: "text-amber-700", bgColor: "bg-amber-50 dark:bg-amber-950/30", borderColor: "border-amber-300", icon: ShieldAlert },
  D: { color: "text-orange-700", bgColor: "bg-orange-50 dark:bg-orange-950/30", borderColor: "border-orange-300", icon: ShieldX },
  F: { color: "text-red-700", bgColor: "bg-red-50 dark:bg-red-950/30", borderColor: "border-red-300", icon: ShieldOff },
};

function GradeBadge({ grade }: { grade?: GradeType }) {
  if (!grade) {
    return (
      <Badge variant="outline" className="text-xs text-muted-foreground">
        —
      </Badge>
    );
  }
  const c = gradeConfig[grade];
  const Icon = c.icon;
  return (
    <Badge variant="outline" className={`gap-1 text-xs font-bold ${c.color} ${c.bgColor} ${c.borderColor}`}>
      <Icon className="size-3" />
      {grade}
    </Badge>
  );
}

function StatsCard({
  label,
  value,
  icon: Icon,
  className,
  iconClassName,
}: {
  label: string;
  value: number;
  icon: React.ComponentType<{ className?: string }>;
  className?: string;
  iconClassName?: string;
}) {
  return (
    <div className={`rounded-lg border bg-card p-4 ${className ?? ""}`}>
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-md bg-muted">
          <Icon className={`size-4 ${iconClassName ?? "text-muted-foreground"}`} />
        </div>
        <div>
          <p className="text-2xl font-bold tabular-nums">{value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </div>
    </div>
  );
}

function SecurityFeatureIcon({ active, icon: Icon, title }: { active?: boolean; icon: React.ComponentType<{ className?: string }>; title: string }) {
  return (
    <div title={title} className="flex items-center">
      <Icon className={`size-3.5 ${active ? "text-emerald-600" : "text-muted-foreground/30"}`} />
    </div>
  );
}

type SiteDoc = Doc<"sites">;

function SiteRow({ site, onClick }: { site: SiteDoc; onClick: () => void }) {
  return (
    <tr
      onClick={onClick}
      className="border-b border-border/50 hover:bg-muted/50 cursor-pointer transition-colors"
    >
      <td className="py-3 px-4">
        <div className="flex flex-col gap-0.5">
          <span className="font-medium text-sm">{site.domain}</span>
          <span className="text-xs text-muted-foreground">
            {site.wpVersion ? `WP ${site.wpVersion}` : ""}
          </span>
        </div>
      </td>
      <td className="py-3 px-4">
        <PhpVersionBadge version={site.phpVersion} checkedAt={site.phpCheckedAt} />
      </td>
      <td className="py-3 px-4">
        <GradeBadge grade={site.securityGrade as GradeType | undefined} />
      </td>
      <td className="py-3 px-4">
        {site.securityScore !== undefined ? (
          <div className="flex items-center gap-2">
            <div className="w-16 h-1.5 rounded-full bg-muted overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  site.securityScore >= 85 ? "bg-emerald-500" :
                  site.securityScore >= 70 ? "bg-blue-500" :
                  site.securityScore >= 50 ? "bg-amber-500" :
                  site.securityScore >= 30 ? "bg-orange-500" :
                  "bg-red-500"
                }`}
                style={{ width: `${site.securityScore}%` }}
              />
            </div>
            <span className="text-xs tabular-nums text-muted-foreground">{site.securityScore}</span>
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </td>
      <td className="py-3 px-4">
        <div className="flex items-center gap-2">
          <SecurityFeatureIcon active={site.hasFirewall} icon={Flame} title="Firewall" />
          <SecurityFeatureIcon active={site.hasMalwareScanner} icon={Bug} title="Malware Scanner" />
          <SecurityFeatureIcon active={site.hasBackup} icon={HardDrive} title="Backup" />
          <SecurityFeatureIcon active={site.hasTwoFactor} icon={KeyRound} title="Two-Factor Auth" />
          <SecurityFeatureIcon active={site.hasBruteForceProtection} icon={Lock} title="Brute Force Protection" />
        </div>
      </td>
      <td className="py-3 px-4">
        {site.totalPlugins !== undefined ? (
          <div className="flex items-center gap-2">
            <span className="text-xs tabular-nums">{site.totalPlugins}</span>
            {(site.pluginsNeedingUpdate ?? 0) > 0 && (
              <Badge
                variant="outline"
                className="text-xs border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-950/30 gap-1"
              >
                <AlertTriangle className="size-3" />
                {site.pluginsNeedingUpdate} outdated
              </Badge>
            )}
          </div>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </td>
      <td className="py-3 px-4">
        {site.wordfenceActive ? (
          <Badge variant="outline" className="text-xs border-emerald-300 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30 gap-1">
            <ShieldCheck className="size-3" />
            Active
          </Badge>
        ) : site.wordfenceInstalled ? (
          <Badge variant="outline" className="text-xs border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-950/30 gap-1">
            <ShieldAlert className="size-3" />
            Inactive
          </Badge>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        )}
      </td>
      <td className="py-3 px-4 text-right">
        <ExternalLink className="size-3.5 text-muted-foreground" />
      </td>
    </tr>
  );
}

export default function DashboardPage() {
  const [search, setSearch] = useState("");
  const [gradeFilter, setGradeFilter] = useState<string>("all");
  const [accountFilter, setAccountFilter] = useState<string>("all");
  const [phpSort, setPhpSort] = useState<"none" | "asc" | "desc">("none");
  const [phpFilter, setPhpFilter] = useState<string>("all");

  const navigate = useNavigate();

  const accounts = useQuery(api.rocketAccounts.list);
  const stats = useQuery(api.sites.stats);
  const vulnStats = useQuery(api.vulnerabilities.stats);
  const sites = useQuery(api.sites.list, {
    grade: gradeFilter === "all" ? undefined : gradeFilter,
    search: search || undefined,
    accountId: accountFilter !== "all" ? (accountFilter as any) : undefined,
  });
  const syncEverything = useAction(api.sync.syncEverything);
  const hasAccounts = useQuery(api.rocketAccounts.hasAny);
  const syncProgress = useQuery(api.settings.getSyncProgress);
  const phpSummary = useQuery(api.phpVersions.summary);

  const visibleSites = (() => {
    if (!sites) return sites;
    let list = [...sites];
    if (phpFilter !== "all") {
      list = list.filter((s) => matchesPhpFilter(s.phpVersion, phpFilter));
    }
    if (phpSort !== "none") {
      list.sort((a, b) => {
        const diff = phpSortValue(a.phpVersion) - phpSortValue(b.phpVersion);
        return phpSort === "asc" ? diff : -diff;
      });
    }
    return list;
  })();

  const isSyncing = syncProgress?.status === "syncing";
  const isDone = syncProgress?.status === "done";
  const isError = syncProgress?.status === "error";

  useEffect(() => {
    if (isDone) {
      const t = setTimeout(() => {
        toast.success(
          `Scan complete: ${syncProgress.completed} of ${syncProgress.total} sites scanned` +
            (syncProgress.errors > 0 ? ` (${syncProgress.errors} errors)` : ""),
        );
      }, 500);
      return () => clearTimeout(t);
    }
  }, [isDone]);

  useEffect(() => {
    if (isError && syncProgress?.phase) {
      toast.error(syncProgress.phase);
    }
  }, [isError]);

  const handleSync = useCallback(async () => {
    if (!hasAccounts) {
      toast.error("No Rocket.net accounts connected. Go to Servers to add one.", {
        action: {
          label: "Go to Servers",
          onClick: () => navigate("/servers"),
        },
      });
      return;
    }
    syncEverything().catch((e) => {
      const msg = e instanceof Error ? e.message : String(e);
      if (!msg.includes("Connection lost")) {
        toast.error("Sync failed. Check your API token.");
      }
    });
    toast.info("Security scan started…");
  }, [syncEverything, hasAccounts, navigate]);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">
            Security Overview
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Monitor security posture across all production sites
          </p>
        </div>
        <div className="flex items-center gap-2">
        <Button
          onClick={handleSync}
          disabled={isSyncing || hasAccounts === undefined}
          variant="outline"
          className="gap-2"
        >
          {isSyncing ? (
            <Loader2 className="size-4 animate-spin" />
          ) : (
            <RefreshCw className="size-4" />
          )}
          {isSyncing ? "Scanning..." : "Scan All Sites"}
        </Button>
        </div>
      </div>

      {/* Sync Progress */}
      {(isSyncing || isDone) && syncProgress && (
        <div className="rounded-lg border bg-card p-4 space-y-3 animate-in fade-in slide-in-from-top-2 duration-300">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {isSyncing ? (
                <Loader2 className="size-4 animate-spin text-red-500" />
              ) : (
                <CheckCircle2 className="size-4 text-emerald-600" />
              )}
              <span className="text-sm font-medium">{syncProgress.phase}</span>
              {syncProgress.currentSite && isSyncing && (
                <span className="text-sm text-muted-foreground">— {syncProgress.currentSite}</span>
              )}
            </div>
            <span className="text-sm tabular-nums text-muted-foreground">
              {syncProgress.total > 0 ? `${syncProgress.completed} / ${syncProgress.total}` : ""}
            </span>
          </div>
          <Progress
            value={syncProgress.total > 0 ? (syncProgress.completed / syncProgress.total) * 100 : isSyncing ? 5 : 0}
            className="h-2"
          />
          {syncProgress.errors > 0 && (
            <p className="text-xs text-amber-600">
              {syncProgress.errors} site{syncProgress.errors > 1 ? "s" : ""} failed
              {syncProgress.errorSites?.length ? `: ${syncProgress.errorSites.join(", ")}` : ""}
            </p>
          )}
        </div>
      )}

      {/* Vulnerability Alert Banner */}
      {vulnStats && vulnStats.open > 0 && (
        <div
          className="rounded-lg border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/20 p-4 flex items-center justify-between cursor-pointer hover:bg-red-100 dark:hover:bg-red-950/30 transition-colors"
          onClick={() => navigate("/vulnerabilities")}
        >
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-md bg-red-100 dark:bg-red-900/30">
              <Bug className="size-5 text-red-600" />
            </div>
            <div>
              <p className="font-semibold text-red-800 dark:text-red-300">
                {vulnStats.open} Open Vulnerabilit{vulnStats.open !== 1 ? "ies" : "y"} Detected
              </p>
              <p className="text-sm text-red-600/80 dark:text-red-400/80">
                {vulnStats.critical > 0 && `${vulnStats.critical} critical · `}
                {vulnStats.high > 0 && `${vulnStats.high} high · `}
                {vulnStats.affectedSites} site{vulnStats.affectedSites !== 1 ? "s" : ""} affected
              </p>
            </div>
          </div>
          <Button variant="outline" size="sm" className="border-red-300 text-red-700 hover:bg-red-100 dark:border-red-700 dark:text-red-400">
            View Details →
          </Button>
        </div>
      )}

      {/* Stats Row */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <StatsCard label="Total Sites" value={stats.total} icon={Server} />
          <StatsCard label="Grade A" value={stats.gradeA} icon={ShieldCheck} iconClassName="text-emerald-600" />
          <StatsCard label="Grade B" value={stats.gradeB} icon={Shield} iconClassName="text-blue-600" />
          <StatsCard label="Grade C–F" value={stats.gradeC + stats.gradeD + stats.gradeF} icon={ShieldAlert} iconClassName="text-amber-600" />
          <StatsCard label="With Firewall" value={stats.withFirewall} icon={Flame} />
          <StatsCard label="Updates Needed" value={stats.pluginUpdatesNeeded} icon={AlertTriangle} iconClassName="text-amber-600" />
        </div>
      )}

      {/* PHP Version Summary */}
      {phpSummary && phpSummary.total > 0 && (
        <div className="rounded-lg border bg-card p-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <Cpu className="size-4 text-muted-foreground" />
              <span className="text-sm font-medium">PHP versions</span>
              {phpSummary.critical > 0 && (
                <Badge variant="outline" className="text-xs border-red-300 text-red-700 bg-red-50 dark:bg-red-950/30 gap-1">
                  <AlertTriangle className="size-3" />
                  {phpSummary.critical} end-of-life
                </Badge>
              )}
            </div>
            <span className="text-xs text-muted-foreground">
              {phpSummary.unknown > 0 && `${phpSummary.unknown} not synced · `}
              {phpSummary.lastCheckedAt
                ? `checked ${new Date(phpSummary.lastCheckedAt).toLocaleString()}`
                : "never checked — runs with the next Sync"}
            </span>
          </div>
          {phpSummary.byVersion.length > 0 && (
            <div className="flex flex-wrap items-center gap-2">
              {phpSummary.byVersion.map((row) => (
                <div key={row.version} className="flex items-center gap-1.5">
                  <PhpVersionBadge version={row.version} />
                  <span className="text-xs tabular-nums text-muted-foreground">×{row.count}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* Filters */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1 max-w-sm">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 size-4 text-muted-foreground" />
          <Input
            placeholder="Search domains..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        {accounts && accounts.length > 1 && (
          <Select value={accountFilter} onValueChange={setAccountFilter}>
            <SelectTrigger className="w-[180px]">
              <SelectValue placeholder="Account" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All accounts</SelectItem>
              {accounts.map((a) => (
                <SelectItem key={a._id} value={a._id}>{a.label}</SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
        <Select value={gradeFilter} onValueChange={setGradeFilter}>
          <SelectTrigger className="w-[160px]">
            <SelectValue placeholder="Grade" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All grades</SelectItem>
            <SelectItem value="A">Grade A</SelectItem>
            <SelectItem value="B">Grade B</SelectItem>
            <SelectItem value="C">Grade C</SelectItem>
            <SelectItem value="D">Grade D</SelectItem>
            <SelectItem value="F">Grade F</SelectItem>
          </SelectContent>
        </Select>
        <Select value={phpFilter} onValueChange={setPhpFilter}>
          <SelectTrigger className="w-[170px]">
            <SelectValue placeholder="PHP version" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">{PHP_FILTER_ALL_LABEL}</SelectItem>
            {PHP_FILTER_OPTIONS.map((o) => (
              <SelectItem key={o.value} value={o.value}>{o.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {visibleSites && (
          <span className="text-sm text-muted-foreground tabular-nums">
            {visibleSites.length} site{visibleSites.length !== 1 ? "s" : ""}
          </span>
        )}
      </div>

      {/* Sites Table */}
      <div className="rounded-lg border bg-card overflow-hidden">
        <table className="w-full">
          <thead>
            <tr className="border-b bg-muted/30">
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Domain</th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">
                <button
                  type="button"
                  onClick={() => setPhpSort((s) => (s === "none" ? "asc" : s === "asc" ? "desc" : "none"))}
                  className="uppercase tracking-wider hover:text-foreground transition-colors"
                  title="Sort by PHP version"
                >
                  PHP {phpSort === "asc" ? "\u2191" : phpSort === "desc" ? "\u2193" : ""}
                </button>
              </th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Grade</th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Score</th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Security Features</th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Plugins</th>
              <th className="py-2.5 px-4 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Wordfence</th>
              <th className="py-2.5 px-4 w-10" />
            </tr>
          </thead>
          <tbody>
            {visibleSites === undefined ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-muted-foreground">Loading...</td>
              </tr>
            ) : visibleSites.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center">
                  <div className="flex flex-col items-center gap-2">
                    <Shield className="size-8 text-muted-foreground/50" />
                    <p className="text-sm text-muted-foreground">
                      {search || gradeFilter !== "all"
                        ? "No sites match your filters"
                        : "No sites yet. Click \"Scan All Sites\" to pull data from Rocket.net."}
                    </p>
                  </div>
                </td>
              </tr>
            ) : (
              visibleSites.map((site) => (
                <SiteRow
                  key={site._id}
                  site={site}
                  onClick={() => navigate(`/site/${site._id}`)}
                />
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
