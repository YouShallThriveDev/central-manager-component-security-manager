import { useMutation, useQuery } from "convex/react";
import type { FunctionReturnType } from "convex/server";
import { Check, Copy, Loader2 } from "lucide-react";
import { useState } from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { api } from "../../convex/_generated/api";
import type { Id } from "../../convex/_generated/dataModel";

type Action = {
  kind: "update_plugin" | "activate_wordfence";
  slug: string;
  name?: string;
  fixedIn?: string;
  status: "pending" | "done" | "failed" | "skipped" | "needs_check";
  fromVersion?: string;
  toVersion?: string;
  prodVersion?: string;
  note?: string;
  reason?: string;
  detail?: string;
  tone?: "attention" | "ok";
};

const STATUS_CLASS: Record<string, string> = {
  queued: "text-muted-foreground",
  pending: "text-muted-foreground",
  running: "border-blue-300 text-blue-700 bg-blue-50 dark:bg-blue-950/30",
  done: "border-emerald-300 text-emerald-700 bg-emerald-50 dark:bg-emerald-950/30",
  failed: "border-red-300 text-red-700 bg-red-50 dark:bg-red-950/30",
  skipped: "border-amber-300 text-amber-700 bg-amber-50 dark:bg-amber-950/30",
  needs_check:
    "border-orange-300 text-orange-700 bg-orange-50 dark:bg-orange-950/30",
};

const statusLabel = (status: string) => status.replace(/_/g, " ");

function StatusBadge({ status, muted }: { status: string; muted?: boolean }) {
  return (
    <Badge
      variant="outline"
      className={`text-xs ${muted ? "text-muted-foreground" : (STATUS_CLASS[status] ?? "")}`}
    >
      {status === "running" && <Loader2 className="animate-spin" />}
      {statusLabel(status)}
    </Badge>
  );
}

function Detail({ text }: { text: string }) {
  const long = text.length > 240 || text.split("\n").length > 4;
  const pre = (
    <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words rounded bg-muted/60 px-2 py-1 font-mono text-[11px] text-muted-foreground">
      {text}
    </pre>
  );
  if (!long) return pre;
  return (
    <details className="group">
      <summary className="cursor-pointer select-none text-[11px] text-muted-foreground hover:text-foreground">
        <span className="group-open:hidden">Show details</span>
        <span className="hidden group-open:inline">Hide details</span>
      </summary>
      <div className="mt-1">{pre}</div>
    </details>
  );
}

function ActionLine({
  action,
  showStatus,
}: {
  action: Action;
  showStatus?: boolean;
}) {
  const label =
    action.kind === "activate_wordfence"
      ? "Activate Wordfence"
      : `Update ${action.name ?? action.slug}`;
  const versions =
    action.kind === "update_plugin"
      ? [
          action.fromVersion && `v${action.fromVersion}`,
          action.toVersion ? `v${action.toVersion}` : "latest",
        ]
          .filter(Boolean)
          .join(" → ")
      : "";
  const why = action.reason ?? action.note;
  const whyClass =
    action.reason && action.tone !== "ok"
      ? "text-amber-700 dark:text-amber-400"
      : "text-muted-foreground";
  return (
    <div className="flex items-start gap-2 text-xs">
      {showStatus && (
        <span className="shrink-0">
          <StatusBadge
            status={action.status}
            muted={action.status === "skipped" && action.tone === "ok"}
          />
        </span>
      )}
      <div className="min-w-0 flex-1 space-y-1 pt-0.5">
        <div className="flex flex-wrap items-baseline gap-x-2 gap-y-0.5">
          <span className="font-medium">{label}</span>
          {versions && (
            <span className="text-muted-foreground tabular-nums">
              {versions}
            </span>
          )}
          {action.fixedIn && !action.toVersion && (
            <span className="text-muted-foreground">
              (fixed in {action.fixedIn})
            </span>
          )}
        </div>
        {why && <p className={`break-words ${whyClass}`}>{why}</p>}
        {action.detail && <Detail text={action.detail} />}
      </div>
    </div>
  );
}

type Job = NonNullable<FunctionReturnType<typeof api.stagingFix.job>>;

const indent = (label: string, text: string) =>
  `  ${label}: ${text.trim().split("\n").join("\n    ")}`;

/** Plain-text report of a job, for pasting into Asana. */
function jobReport(job: Job): string {
  const lines = [
    `Fix on staging — ${new Date(job._creationTime).toLocaleString()} — ${job.status === "running" ? "running" : "finished"}`,
  ];
  for (const i of job.items) {
    lines.push(
      "",
      `${i.domain}${i.stagingSiteId ? ` (staging #${i.stagingSiteId})` : ""} — ${statusLabel(i.status)}`,
    );
    if (i.error)
      lines.push(indent(i.status === "skipped" ? "Reason" : "Error", i.error));
    if (i.status === "skipped") continue;
    for (const a of i.actions) {
      const label =
        a.kind === "activate_wordfence"
          ? "Activate Wordfence"
          : `Update ${a.name ?? a.slug}`;
      const versions =
        a.kind === "update_plugin"
          ? [a.fromVersion, a.toVersion].filter(Boolean).join(" → ")
          : "";
      const extra = [
        a.fixedIn && `fixed in ${a.fixedIn}`,
        a.prodVersion &&
          a.prodVersion !== a.fromVersion &&
          `live ${a.prodVersion}`,
      ]
        .filter(Boolean)
        .join(", ");
      const why = a.reason ?? a.note;
      lines.push(
        `- ${label}${versions ? ` ${versions}` : ""}${extra ? ` (${extra})` : ""}: ${statusLabel(a.status)}${why ? ` — ${why}` : ""}`,
      );
      if (a.detail) lines.push(indent("Detail", a.detail));
    }
  }
  return lines.join("\n");
}

function CopyReport({ job }: { job: Job }) {
  const text = jobReport(job);
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      toast.error("Couldn't copy — select the text and copy it manually");
    }
  };
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <span className="text-xs font-medium text-muted-foreground">
          Report (for Asana)
        </span>
        <Button size="sm" variant="outline" onClick={copy}>
          {copied ? <Check className="size-4" /> : <Copy className="size-4" />}
          {copied ? "Copied" : "Copy"}
        </Button>
      </div>
      <textarea
        readOnly
        value={text}
        onFocus={e => e.currentTarget.select()}
        className="h-32 w-full resize-y rounded-md border bg-muted/40 px-2 py-1.5 font-mono text-[11px] leading-snug"
      />
    </div>
  );
}

function PlanView({
  siteIds,
  onStarted,
  onCancel,
}: {
  siteIds: Id<"sites">[];
  onStarted: (jobId: Id<"stagingFixJobs">) => void;
  onCancel: () => void;
}) {
  const plans = useQuery(api.stagingFix.plan, { siteIds });
  const start = useMutation(api.stagingFix.start);
  const [starting, setStarting] = useState(false);
  const runnable = plans?.filter(p => !p.skipReason) ?? [];

  const handleStart = async () => {
    setStarting(true);
    try {
      onStarted(await start({ siteIds }));
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Failed to start");
    } finally {
      setStarting(false);
    }
  };

  return (
    <>
      <DialogHeader>
        <DialogTitle>Fix on staging — dry run</DialogTitle>
        <DialogDescription>
          Changes apply only to each site's Rocket.net staging copy. Live sites
          are never touched.
          {plans &&
            ` ${runnable.length} will run, ${plans.length - runnable.length} skipped.`}
        </DialogDescription>
      </DialogHeader>
      <div className="max-h-[55vh] overflow-y-auto rounded-md border divide-y">
        {plans === undefined ? (
          <div className="p-6 text-center text-sm text-muted-foreground">
            Building plan…
          </div>
        ) : (
          plans.map(p => (
            <div key={p.siteId} className="p-3 space-y-1.5">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{p.domain}</span>
                {p.skipReason && <StatusBadge status="skipped" />}
                {p.skipReason && (
                  <span className="text-xs text-muted-foreground">
                    {p.skipReason}
                  </span>
                )}
              </div>
              {!p.skipReason &&
                p.actions.map(a => <ActionLine key={a.slug} action={a} />)}
            </div>
          ))
        )}
      </div>
      <DialogFooter>
        <Button variant="outline" onClick={onCancel}>
          Cancel
        </Button>
        <Button
          onClick={handleStart}
          disabled={!plans || runnable.length === 0 || starting}
        >
          {starting && <Loader2 className="size-4 animate-spin" />}
          Run on {runnable.length} staging site
          {runnable.length !== 1 ? "s" : ""}
        </Button>
      </DialogFooter>
    </>
  );
}

function JobView({ jobId }: { jobId: Id<"stagingFixJobs"> }) {
  const job = useQuery(api.stagingFix.job, { jobId });
  const counts = new Map<string, number>();
  for (const i of job?.items ?? [])
    counts.set(i.status, (counts.get(i.status) ?? 0) + 1);

  return (
    <>
      <DialogHeader>
        <DialogTitle className="flex items-center gap-2">
          Fix on staging
          {job?.status === "running" && (
            <Loader2 className="size-4 animate-spin" />
          )}
        </DialogTitle>
        <DialogDescription>
          {job
            ? `Started ${new Date(job._creationTime).toLocaleString()} · ${job.status === "running" ? "running" : "finished"}`
            : "Loading…"}
        </DialogDescription>
      </DialogHeader>
      {job && (
        <div className="flex flex-wrap gap-2">
          {["queued", "running", "done", "failed", "skipped"].map(
            s =>
              (counts.get(s) ?? 0) > 0 && (
                <span
                  key={s}
                  className="flex items-center gap-1 text-xs tabular-nums"
                >
                  <StatusBadge status={s} />
                  {counts.get(s)}
                </span>
              ),
          )}
        </div>
      )}
      <div className="max-h-[55vh] overflow-y-auto rounded-md border divide-y">
        {job?.items.map(i => (
          <div key={i._id} className="p-3 space-y-1.5">
            <div className="flex items-center gap-2">
              <StatusBadge status={i.status} />
              <span className="text-sm font-medium">{i.domain}</span>
              {i.stagingSiteId && (
                <span className="text-xs text-muted-foreground tabular-nums">
                  staging #{i.stagingSiteId}
                </span>
              )}
            </div>
            {i.error && (
              <p className="text-xs text-red-600 break-words">{i.error}</p>
            )}
            {i.status !== "skipped" &&
              i.actions.map(a => (
                <ActionLine key={a.slug} action={a} showStatus />
              ))}
          </div>
        ))}
      </div>
      {job?.status === "done" && (
        <p className="text-xs text-muted-foreground">
          Versions are re-read from staging after each change. Review staging
          before pushing anything live.
        </p>
      )}
      {job && <CopyReport job={job} />}
    </>
  );
}

export function StagingFixDialog({
  open,
  onOpenChange,
  siteIds,
  jobId,
  onJobStarted,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  siteIds: Id<"sites">[];
  jobId: Id<"stagingFixJobs"> | null;
  onJobStarted: (jobId: Id<"stagingFixJobs">) => void;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-2xl">
        {jobId ? (
          <JobView jobId={jobId} />
        ) : (
          open && (
            <PlanView
              siteIds={siteIds}
              onStarted={onJobStarted}
              onCancel={() => onOpenChange(false)}
            />
          )
        )}
      </DialogContent>
    </Dialog>
  );
}
