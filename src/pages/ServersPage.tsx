import { useQuery, useAction } from "convex/react";
import { api } from "../../convex/_generated/api";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Server,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ExternalLink,
  RefreshCw,
} from "lucide-react";
import { toast } from "sonner";

const SERVER_MANAGEMENT_URL = import.meta.env.VITE_SERVER_MANAGEMENT_URL || "https://preview-server-management-8973432e.viktor.space";

function AccountCard({ account }: { account: any }) {
  return (
    <div className="rounded-lg border bg-card p-5 space-y-4">
      <div className="flex items-start justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 rounded-md bg-muted">
            <Server className="size-5 text-muted-foreground" />
          </div>
          <div>
            <p className="font-semibold">{account.label}</p>
            <p className="text-xs text-muted-foreground mt-0.5">
              Token: {account.tokenPreview}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1">
          {account.status === "connected" && (
            <Badge variant="outline" className="text-xs gap-1 border-emerald-300 text-emerald-600 bg-emerald-50 dark:bg-emerald-950/30">
              <CheckCircle2 className="size-3" />
              Connected
            </Badge>
          )}
          {account.status === "expired" && (
            <Badge variant="outline" className="text-xs gap-1 border-amber-300 text-amber-600 bg-amber-50 dark:bg-amber-950/30">
              <AlertTriangle className="size-3" />
              Token Expired
            </Badge>
          )}
          {account.status === "error" && (
            <Badge variant="outline" className="text-xs gap-1 border-red-300 text-red-600 bg-red-50 dark:bg-red-950/30">
              <XCircle className="size-3" />
              Error
            </Badge>
          )}
        </div>
      </div>

      <div className="flex items-center gap-4 text-sm text-muted-foreground">
        {account.siteCount !== undefined && (
          <span>{account.siteCount} sites</span>
        )}
        {account.lastSyncedAt && (
          <span>Last synced: {new Date(account.lastSyncedAt).toLocaleString()}</span>
        )}
      </div>

      {account.lastError && (
        <div className="p-3 rounded-md bg-red-50 dark:bg-red-950/20 text-sm text-red-600 dark:text-red-400">
          {account.lastError}
        </div>
      )}
    </div>
  );
}

export default function ServersPage() {
  const accounts = useQuery(api.rocketAccounts.list);
  const syncAll = useAction(api.sync.syncEverything);
  const [syncing, setSyncing] = useState(false);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const result = await syncAll();
      toast.success(`Synced ${result.sitesSynced} sites, scanned ${result.sitesScanned}${result.errors > 0 ? `, ${result.errors} errors` : ""}`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Sync failed");
    } finally {
      setSyncing(false);
    }
  };

  return (
    <div className="p-6 max-w-[800px] mx-auto space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Servers</h1>
          <p className="text-sm text-muted-foreground mt-1">
            Rocket.net hosting accounts (managed in Server Management)
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            onClick={handleSync}
            disabled={syncing}
            className="gap-2"
          >
            <RefreshCw className={`size-4 ${syncing ? "animate-spin" : ""}`} />
            {syncing ? "Syncing…" : "Sync Now"}
          </Button>
          <Button
            variant="outline"
            onClick={() => window.open(SERVER_MANAGEMENT_URL, "_blank")}
            className="gap-2"
          >
            <ExternalLink className="size-4" />
            Manage Credentials
          </Button>
        </div>
      </div>

      {/* Info banner */}
      <div className="rounded-lg border border-indigo-200 bg-indigo-50 dark:bg-indigo-950/20 dark:border-indigo-800 p-4 flex items-start gap-3">
        <Server className="size-5 text-indigo-600 dark:text-indigo-400 mt-0.5 shrink-0" />
        <div className="text-sm">
          <p className="font-medium text-indigo-700 dark:text-indigo-300">
            Credentials are managed centrally
          </p>
          <p className="text-indigo-600/80 dark:text-indigo-400/80 mt-0.5">
            API keys are now stored in{" "}
            <a
              href={SERVER_MANAGEMENT_URL}
              target="_blank"
              rel="noopener noreferrer"
              className="underline hover:text-indigo-700 dark:hover:text-indigo-300"
            >
              Server Management
            </a>
            . Credentials sync automatically when you run a security scan.
          </p>
        </div>
      </div>

      {accounts === undefined ? (
        <div className="animate-pulse space-y-4">
          <div className="h-32 bg-muted rounded-lg" />
        </div>
      ) : accounts.length === 0 ? (
        <div className="rounded-lg border bg-card p-12 text-center">
          <Server className="size-12 text-muted-foreground/30 mx-auto mb-3" />
          <h3 className="font-semibold text-lg mb-1">No accounts connected</h3>
          <p className="text-sm text-muted-foreground mb-4">
            Add a Rocket.net API key in Server Management, then sync here to start scanning.
          </p>
          <div className="flex items-center justify-center gap-2">
            <Button
              onClick={() => window.open(SERVER_MANAGEMENT_URL, "_blank")}
              className="gap-2"
            >
              <ExternalLink className="size-4" />
              Open Server Management
            </Button>
            <Button
              variant="outline"
              onClick={handleSync}
              disabled={syncing}
              className="gap-2"
            >
              <RefreshCw className={`size-4 ${syncing ? "animate-spin" : ""}`} />
              {syncing ? "Syncing…" : "Sync Credentials"}
            </Button>
          </div>
        </div>
      ) : (
        <div className="space-y-4">
          {accounts.map((account) => (
            <AccountCard key={account._id} account={account} />
          ))}
        </div>
      )}
    </div>
  );
}
