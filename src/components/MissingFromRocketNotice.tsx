import { useState } from "react";
import { useMutation } from "convex/react";
import { useNavigate } from "react-router-dom";
import { api } from "../../convex/_generated/api";
import { Button } from "@/components/ui/button";
import { AlertTriangle, Trash2 } from "lucide-react";

/**
 * Shown on a site detail page when Rocket.net no longer returns the site.
 *
 * The record is deliberately kept — nothing deletes site records automatically.
 * Removing one is an explicit human action, confirmed here.
 */
export function MissingFromRocketNotice({
  siteId,
  status,
  missingSince,
  domain,
}: {
  siteId: string;
  status?: string;
  missingSince?: number;
  domain: string;
}) {
  const [confirming, setConfirming] = useState(false);
  const [removing, setRemoving] = useState(false);
  const removeSite = useMutation(api.sites.removeSite);
  const navigate = useNavigate();

  if (status !== "missing" && status !== "auth_error") return null;

  const isMissing = status === "missing";

  const handleRemove = async () => {
    setRemoving(true);
    try {
      await removeSite({ siteId: siteId as any });
      navigate("/dashboard");
    } finally {
      setRemoving(false);
    }
  };

  return (
    <div
      className={`rounded-lg border p-4 ${
        isMissing
          ? "border-red-300 bg-red-50 dark:bg-red-950/20"
          : "border-amber-300 bg-amber-50 dark:bg-amber-950/20"
      }`}
    >
      <div className="flex items-start gap-3">
        <AlertTriangle
          className={`size-5 mt-0.5 ${isMissing ? "text-red-600" : "text-amber-600"}`}
        />
        <div className="flex-1 space-y-1">
          <p className="font-medium text-sm">
            {isMissing ? "Missing from Rocket.net" : "Rocket.net read failed"}
          </p>
          <p className="text-sm text-muted-foreground">
            {isMissing
              ? `Rocket.net no longer returns ${domain}${
                  missingSince
                    ? `, first seen missing on ${new Date(missingSince).toLocaleDateString()}`
                    : ""
                }. The record is kept here on purpose — remove it only if the site was retired deliberately.`
              : `Rocket.net rejected the last read for ${domain} (token or permission). This is not proof the site is gone.`}
          </p>
        </div>
        {isMissing &&
          (confirming ? (
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="destructive"
                onClick={handleRemove}
                disabled={removing}
              >
                {removing ? "Removing..." : "Confirm remove"}
              </Button>
              <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>
                Cancel
              </Button>
            </div>
          ) : (
            <Button size="sm" variant="outline" onClick={() => setConfirming(true)}>
              <Trash2 className="size-4 mr-1" />
              Remove record
            </Button>
          ))}
      </div>
    </div>
  );
}
