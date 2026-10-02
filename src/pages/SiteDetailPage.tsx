import { useQuery } from "convex/react";
import { api } from "../../convex/_generated/api";
import { PhpVersionBadge } from "@/components/PhpVersionBadge";
import { RocketStatusBadge } from "@/components/RocketStatusBadge";
import { MissingFromRocketNotice } from "@/components/MissingFromRocketNotice";
import { useParams, Link } from "react-router-dom";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  ArrowLeft,
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  ShieldOff,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Flame,
  Bug,
  HardDrive,
  KeyRound,
  Lock,
  Plug,
  ExternalLink,
  Globe,
  Server,
} from "lucide-react";

type GradeType = "A" | "B" | "C" | "D" | "F";

const gradeConfig: Record<GradeType, { color: string; bgColor: string; borderColor: string; icon: typeof ShieldCheck; label: string }> = {
  A: { color: "text-emerald-700 dark:text-emerald-400", bgColor: "bg-emerald-50 dark:bg-emerald-950/30", borderColor: "border-emerald-200", icon: ShieldCheck, label: "Excellent" },
  B: { color: "text-blue-700 dark:text-blue-400", bgColor: "bg-blue-50 dark:bg-blue-950/30", borderColor: "border-blue-200", icon: Shield, label: "Good" },
  C: { color: "text-amber-700 dark:text-amber-400", bgColor: "bg-amber-50 dark:bg-amber-950/30", borderColor: "border-amber-200", icon: ShieldAlert, label: "Fair" },
  D: { color: "text-orange-700 dark:text-orange-400", bgColor: "bg-orange-50 dark:bg-orange-950/30", borderColor: "border-orange-200", icon: ShieldX, label: "Poor" },
  F: { color: "text-red-700 dark:text-red-400", bgColor: "bg-red-50 dark:bg-red-950/30", borderColor: "border-red-200", icon: ShieldOff, label: "Critical" },
};

const categoryLabels: Record<string, { label: string; icon: typeof Flame }> = {
  firewall: { label: "Firewall / WAF", icon: Flame },
  malware: { label: "Malware Scanner", icon: Bug },
  "brute-force": { label: "Brute Force Protection", icon: Lock },
  "two-factor": { label: "Two-Factor Auth", icon: KeyRound },
  backup: { label: "Backup", icon: HardDrive },
  "general-security": { label: "General Security", icon: Shield },
  monitoring: { label: "Monitoring / Audit", icon: Globe },
};

function FeatureCard({
  title,
  active,
  icon: Icon,
}: {
  title: string;
  active?: boolean;
  icon: React.ComponentType<{ className?: string }>;
}) {
  return (
    <div
      className={`rounded-lg border p-4 flex items-center gap-3 ${
        active
          ? "bg-emerald-50 dark:bg-emerald-950/20 border-emerald-200"
          : "bg-muted/30 border-border"
      }`}
    >
      <div className={`p-2 rounded-md ${active ? "bg-emerald-100 dark:bg-emerald-900/30" : "bg-muted"}`}>
        <Icon className={`size-4 ${active ? "text-emerald-600" : "text-muted-foreground/50"}`} />
      </div>
      <div className="flex-1">
        <p className="text-sm font-medium">{title}</p>
        <p className={`text-xs ${active ? "text-emerald-600" : "text-muted-foreground"}`}>
          {active ? "Active" : "Not detected"}
        </p>
      </div>
      {active ? (
        <CheckCircle2 className="size-4 text-emerald-600" />
      ) : (
        <XCircle className="size-4 text-muted-foreground/30" />
      )}
    </div>
  );
}

export default function SiteDetailPage() {
  const { siteId } = useParams<{ siteId: string }>();
  const site = useQuery(api.sites.get, siteId ? { id: siteId as any } : "skip");
  const plugins = useQuery(
    api.sitePlugins.listBySite,
    siteId ? { siteId: siteId as any } : "skip",
  );
  const muPlugins = useQuery(
    api.siteMuPlugins.listBySite,
    siteId ? { siteId: siteId as any } : "skip",
  );
  const siteVulns = useQuery(
    api.vulnerabilities.bySite,
    siteId ? { siteId: siteId as any } : "skip",
  );

  if (site === undefined || plugins === undefined) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto">
        <div className="animate-pulse space-y-4">
          <div className="h-8 w-48 bg-muted rounded" />
          <div className="h-64 bg-muted rounded-lg" />
        </div>
      </div>
    );
  }

  if (site === null) {
    return (
      <div className="p-6 max-w-[1200px] mx-auto">
        <p className="text-muted-foreground">Site not found.</p>
        <Button asChild variant="ghost" className="mt-4">
          <Link to="/dashboard">
            <ArrowLeft className="size-4 mr-2" />
            Back to dashboard
          </Link>
        </Button>
      </div>
    );
  }

  const grade = site.securityGrade as GradeType | undefined;
  const gc = grade ? gradeConfig[grade] : null;
  const GradeIcon = gc?.icon ?? Shield;

  const securityPlugins = plugins?.filter((p) => p.isSecurityPlugin) ?? [];
  const activeSecurityPlugins = securityPlugins.filter((p) => p.status === "active");
  const inactiveSecurityPlugins = securityPlugins.filter((p) => p.status === "inactive");
  const outdatedPlugins = plugins?.filter((p) => p.updateAvailable) ?? [];
  const allActivePlugins = plugins?.filter((p) => p.status === "active") ?? [];

  return (
    <div className="p-6 max-w-[1200px] mx-auto space-y-6">
      {/* Back & Header */}
      <div className="flex items-center gap-4">
        <Button asChild variant="ghost" size="sm">
          <Link to="/dashboard">
            <ArrowLeft className="size-4 mr-1" />
            Back
          </Link>
        </Button>
      </div>

      <MissingFromRocketNotice
        siteId={site._id}
        status={site.rocketStatus}
        missingSince={site.rocketMissingSince}
        domain={site.domain}
      />

      <div className="flex items-start justify-between">
        <div className="space-y-1">
          <h1 className="text-2xl font-bold tracking-tight">{site.domain}</h1>
          <div className="flex items-center gap-3 text-sm text-muted-foreground">
            <PhpVersionBadge version={site.phpVersion} checkedAt={site.phpCheckedAt} />
            <RocketStatusBadge status={site.rocketStatus} missingSince={site.rocketMissingSince} />
            {site.wpVersion && <span>WP {site.wpVersion}</span>}
            {site.rocketUrl && (
              <a
                href={site.rocketUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center gap-1 hover:text-foreground transition-colors"
              >
                <Server className="size-3" />
                Rocket.net
                <ExternalLink className="size-3" />
              </a>
            )}
            <a
              href={`https://${site.domain}`}
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center gap-1 hover:text-foreground transition-colors"
            >
              <Globe className="size-3" />
              Visit site
              <ExternalLink className="size-3" />
            </a>
          </div>
        </div>
      </div>

      {/* Security Grade Hero */}
      <div className={`rounded-xl border-2 p-6 ${gc?.bgColor ?? "bg-muted/30"} ${gc?.borderColor ?? "border-border"}`}>
        <div className="flex items-center gap-6">
          <div className={`text-6xl font-black tabular-nums ${gc?.color ?? "text-muted-foreground"}`}>
            {grade ?? "?"}
          </div>
          <div className="flex-1">
            <div className="flex items-center gap-2">
              <GradeIcon className={`size-5 ${gc?.color ?? "text-muted-foreground"}`} />
              <span className={`text-lg font-semibold ${gc?.color ?? ""}`}>
                {gc?.label ?? "Not Scanned"}
              </span>
            </div>
            <p className="text-sm text-muted-foreground mt-1">
              Security score: <strong className="tabular-nums">{site.securityScore ?? 0}</strong> / 100
            </p>
            {(site.vulnPenalty ?? 0) > 0 && (
              <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                Base <span className="tabular-nums">{site.securityBaseScore ?? 0}</span> − <span className="tabular-nums">{site.vulnPenalty}</span> for open vulnerabilities
                {" "}({[
                  site.openVulnCritical ? `${site.openVulnCritical} critical` : null,
                  site.openVulnHigh ? `${site.openVulnHigh} high` : null,
                  site.openVulnMedium ? `${site.openVulnMedium} medium` : null,
                  site.openVulnLow ? `${site.openVulnLow} low` : null,
                ].filter(Boolean).join(", ")})
                {site.vulnGradeCap && <> · grade capped at {site.vulnGradeCap}</>}
              </p>
            )}
            <div className="w-full max-w-md mt-2 h-2.5 rounded-full bg-black/10 dark:bg-white/10 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${
                  (site.securityScore ?? 0) >= 85 ? "bg-emerald-500" :
                  (site.securityScore ?? 0) >= 70 ? "bg-blue-500" :
                  (site.securityScore ?? 0) >= 50 ? "bg-amber-500" :
                  (site.securityScore ?? 0) >= 30 ? "bg-orange-500" :
                  "bg-red-500"
                }`}
                style={{ width: `${site.securityScore ?? 0}%` }}
              />
            </div>
          </div>
          <div className="text-right">
            <p className="text-xs text-muted-foreground">Last scanned</p>
            <p className="text-sm">
              {site.lastSyncedAt
                ? new Date(site.lastSyncedAt).toLocaleString()
                : "Never"}
            </p>
          </div>
        </div>
      </div>

      {/* Security Features Grid */}
      <div>
        <h2 className="text-lg font-semibold mb-3">Security Features</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          <FeatureCard title="Firewall / WAF" active={site.hasFirewall} icon={Flame} />
          <FeatureCard title="Malware Scanner" active={site.hasMalwareScanner} icon={Bug} />
          <FeatureCard title="Backup Solution" active={site.hasBackup} icon={HardDrive} />
          <FeatureCard title="Two-Factor Auth" active={site.hasTwoFactor} icon={KeyRound} />
          <FeatureCard title="Brute Force Protection" active={site.hasBruteForceProtection} icon={Lock} />
          <FeatureCard title="SSL Certificate" active={site.sslEnabled} icon={Globe} />
        </div>
      </div>

      {/* Wordfence Status */}
      {site.wordfenceInstalled && (
        <div className="rounded-lg border bg-card p-5">
          <div className="flex items-center gap-3 mb-3">
            <div className="p-2 rounded-md bg-red-100 dark:bg-red-900/20">
              <Shield className="size-5 text-red-600" />
            </div>
            <div>
              <h2 className="text-lg font-semibold">Wordfence</h2>
              <p className="text-sm text-muted-foreground">
                Version {site.wordfenceVersion ?? "unknown"} ·{" "}
                {site.wordfenceActive ? (
                  <span className="text-emerald-600 font-medium">Active</span>
                ) : (
                  <span className="text-amber-600 font-medium">Inactive</span>
                )}
              </p>
            </div>
          </div>
          {site.lastScanResult && (
            <div className="mt-3 p-3 rounded-md bg-muted/50 font-mono text-xs whitespace-pre-wrap">
              {site.lastScanResult}
            </div>
          )}
        </div>
      )}

      {/* Vulnerabilities */}
      {siteVulns && siteVulns.filter(v => v.status === "open").length > 0 && (
        <div className="rounded-lg border border-red-300 dark:border-red-800 bg-card overflow-hidden">
          <div className="p-4 border-b bg-red-50 dark:bg-red-950/20 flex items-center gap-2">
            <AlertTriangle className="size-4 text-red-600" />
            <h2 className="text-sm font-semibold text-red-800 dark:text-red-300">
              Vulnerabilities ({siteVulns.filter(v => v.status === "open").length} open)
            </h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b text-xs text-muted-foreground">
                <th className="py-2 px-4 text-left font-medium">Vulnerability</th>
                <th className="py-2 px-4 text-left font-medium">Plugin / theme</th>
                <th className="py-2 px-4 text-left font-medium">Severity</th>
                <th className="py-2 px-4 text-left font-medium">Fix</th>
              </tr>
            </thead>
            <tbody>
              {siteVulns.filter(v => v.status === "open").map((v) => (
                <tr key={v._id} className="border-b border-border/50">
                  <td className="py-2.5 px-4">
                    <div className="flex flex-col gap-0.5">
                      <span className="text-sm font-medium">{v.title}</span>
                      {v.cveId && <span className="text-xs text-muted-foreground font-mono">{v.cveId}</span>}
                    </div>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="text-sm">{v.pluginSlug}</span>
                    {v.pluginVersion && <span className="text-xs text-muted-foreground ml-1">v{v.pluginVersion}</span>}
                    {v.componentType === "theme" && (
                      <Badge variant="outline" className="ml-1.5 text-[10px] px-1.5 py-0 border-violet-300 text-violet-700 bg-violet-50 dark:bg-violet-950/30">
                        Theme
                      </Badge>
                    )}
                  </td>
                  <td className="py-2.5 px-4">
                    <Badge
                      variant="outline"
                      className={`text-xs font-bold ${
                        v.severity === "critical" ? "border-red-300 text-red-700 bg-red-50 dark:bg-red-950/30" :
                        v.severity === "high" ? "border-orange-300 text-orange-700 bg-orange-50 dark:bg-orange-950/30" :
                        v.severity === "medium" ? "border-amber-300 text-amber-700 bg-amber-50 dark:bg-amber-950/30" :
                        "border-blue-300 text-blue-700 bg-blue-50 dark:bg-blue-950/30"
                      }`}
                    >
                      {v.severity}
                      {v.cvssScore !== undefined && ` (${v.cvssScore.toFixed(1)})`}
                    </Badge>
                  </td>
                  <td className="py-2.5 px-4">
                    {v.fixedInVersion ? (
                      <Badge variant="outline" className="text-xs border-emerald-300 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30">
                        → v{v.fixedInVersion}
                      </Badge>
                    ) : (
                      <span className="text-xs text-muted-foreground">No fix yet</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Active Security Plugins */}
      <div className="rounded-lg border bg-card overflow-hidden">
        <div className="p-4 border-b bg-muted/30 flex items-center justify-between">
          <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Security Plugins ({activeSecurityPlugins.length} active, {inactiveSecurityPlugins.length} inactive)
          </h2>
        </div>
        {securityPlugins.length === 0 ? (
          <div className="p-8 text-center">
            <ShieldOff className="size-8 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">No security plugins detected</p>
          </div>
        ) : (
          <table className="w-full">
            <thead>
              <tr className="border-b text-xs text-muted-foreground">
                <th className="py-2 px-4 text-left font-medium">Plugin / theme</th>
                <th className="py-2 px-4 text-left font-medium">Category</th>
                <th className="py-2 px-4 text-left font-medium">Version</th>
                <th className="py-2 px-4 text-left font-medium">Status</th>
              </tr>
            </thead>
            <tbody>
              {securityPlugins.map((p) => {
                const cat = p.securityCategory ? categoryLabels[p.securityCategory] : null;
                const CatIcon = cat?.icon ?? Plug;
                return (
                  <tr key={p._id} className="border-b border-border/50">
                    <td className="py-2.5 px-4">
                      <span className="text-sm font-medium">{p.displayName || p.slug}</span>
                    </td>
                    <td className="py-2.5 px-4">
                      {cat ? (
                        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                          <CatIcon className="size-3" />
                          {cat.label}
                        </div>
                      ) : (
                        <span className="text-xs text-muted-foreground">—</span>
                      )}
                    </td>
                    <td className="py-2.5 px-4">
                      <span className="text-xs tabular-nums">{p.version ?? "—"}</span>
                      {p.updateAvailable && (
                        <Badge variant="outline" className="ml-2 text-xs border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-950/30">
                          Update
                        </Badge>
                      )}
                    </td>
                    <td className="py-2.5 px-4">
                      <Badge
                        variant="outline"
                        className={`text-xs ${
                          p.status === "active"
                            ? "border-emerald-300 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30"
                            : "border-border text-muted-foreground"
                        }`}
                      >
                        {p.status}
                      </Badge>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>

      {/* Outdated Plugins */}
      {outdatedPlugins.length > 0 && (
        <div className="rounded-lg border bg-card overflow-hidden">
          <div className="p-4 border-b bg-amber-50 dark:bg-amber-950/20 flex items-center gap-2">
            <AlertTriangle className="size-4 text-amber-600" />
            <h2 className="text-sm font-semibold text-amber-800 dark:text-amber-300">
              Plugins Needing Updates ({outdatedPlugins.length})
            </h2>
          </div>
          <table className="w-full">
            <tbody>
              {outdatedPlugins.map((p) => (
                <tr key={p._id} className="border-b border-border/50">
                  <td className="py-2.5 px-4">
                    <span className="text-sm">{p.displayName || p.slug}</span>
                  </td>
                  <td className="py-2.5 px-4">
                    <span className="text-xs tabular-nums text-muted-foreground">{p.version ?? "—"}</span>
                  </td>
                  <td className="py-2.5 px-4">
                    <Badge
                      variant="outline"
                      className={`text-xs ${
                        p.status === "active"
                          ? "border-emerald-300 text-emerald-600"
                          : "border-border text-muted-foreground"
                      }`}
                    >
                      {p.status}
                    </Badge>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* All Active Plugins */}
      <details className="rounded-lg border bg-card overflow-hidden group">
        <summary className="p-4 cursor-pointer hover:bg-muted/30 transition-colors flex items-center gap-2">
          <Plug className="size-4 text-muted-foreground" />
          <span className="text-sm font-medium">
            All Active Plugins ({allActivePlugins.length})
          </span>
        </summary>
        <div className="border-t">
          <table className="w-full">
            <tbody>
              {allActivePlugins.map((p) => (
                <tr key={p._id} className="border-b border-border/50 last:border-0">
                  <td className="py-2 px-4">
                    <span className="text-sm">{p.displayName || p.slug}</span>
                  </td>
                  <td className="py-2 px-4">
                    <span className="text-xs tabular-nums text-muted-foreground">{p.version ?? ""}</span>
                  </td>
                  <td className="py-2 px-4">
                    {p.isSecurityPlugin && (
                      <Badge variant="outline" className="text-xs border-red-200 text-red-600 bg-red-50 dark:bg-red-950/30">
                        Security
                      </Badge>
                    )}
                    {p.updateAvailable && (
                      <Badge variant="outline" className="text-xs border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-950/30 ml-1">
                        Update
                      </Badge>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </details>

      {/* MU-Plugins */}
      {muPlugins && muPlugins.length > 0 && (
        <details className="rounded-lg border bg-card overflow-hidden">
          <summary className="p-4 cursor-pointer hover:bg-muted/30 transition-colors flex items-center gap-2">
            <Server className="size-4 text-muted-foreground" />
            <span className="text-sm font-medium">
              MU-Plugins ({muPlugins.length})
            </span>
          </summary>
          <div className="border-t">
            <table className="w-full">
              <tbody>
                {muPlugins.map((m) => (
                  <tr key={m._id} className="border-b border-border/50 last:border-0">
                    <td className="py-2 px-4">
                      <span className="text-sm font-mono">{m.filename}</span>
                    </td>
                    <td className="py-2 px-4">
                      {m.isSecurityRelated && (
                        <Badge variant="outline" className="text-xs border-red-200 text-red-600 bg-red-50 dark:bg-red-950/30">
                          Security
                        </Badge>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </details>
      )}
    </div>
  );
}
