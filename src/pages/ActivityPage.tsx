import { useQuery } from "convex/react";
import { api } from "../../convex/_generated/api";
import { Badge } from "@/components/ui/badge";
import { Activity, CheckCircle2, AlertTriangle, Info } from "lucide-react";

export default function ActivityPage() {
  const logs = useQuery(api.actionLogs.list, { limit: 200 });

  return (
    <div className="p-6 max-w-[800px] mx-auto space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">Activity Log</h1>
        <p className="text-sm text-muted-foreground mt-1">
          Recent sync and scan activity
        </p>
      </div>

      <div className="rounded-lg border bg-card overflow-hidden">
        {logs === undefined ? (
          <div className="p-8 text-center text-muted-foreground">Loading...</div>
        ) : logs.length === 0 ? (
          <div className="p-12 text-center">
            <Activity className="size-8 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground">No activity yet</p>
          </div>
        ) : (
          <div className="divide-y">
            {logs.map((log) => (
              <div key={log._id} className="p-4 flex items-start gap-3">
                <div className="mt-0.5">
                  {log.status === "success" && (
                    <CheckCircle2 className="size-4 text-emerald-600" />
                  )}
                  {log.status === "error" && (
                    <AlertTriangle className="size-4 text-red-600" />
                  )}
                  {log.status === "info" && (
                    <Info className="size-4 text-blue-600" />
                  )}
                </div>
                <div className="flex-1 min-w-0">
                  <p className="text-sm">{log.details}</p>
                  <div className="flex items-center gap-2 mt-1">
                    <Badge variant="outline" className="text-xs">
                      {log.action}
                    </Badge>
                    <span className="text-xs text-muted-foreground">
                      {new Date(log._creationTime).toLocaleString()}
                    </span>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
