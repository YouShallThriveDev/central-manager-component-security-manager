import { useAuthActions } from "@convex-dev/auth/react";
import { useConvexAuth } from "convex/react";
import { useEffect, useRef, useState } from "react";
import { useSearchParams, useNavigate, Outlet } from "react-router-dom";
import { Loader2 } from "lucide-react";

/**
 * Wraps routes to intercept ?sso_token= and auto-sign-in.
 * Shows a loading spinner during SSO login, then renders children.
 */
export function SSOGate() {
  const { signIn } = useAuthActions();
  const { isAuthenticated, isLoading } = useConvexAuth();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const attempted = useRef(false);
  const [ssoInProgress, setSsoInProgress] = useState(false);

  const ssoToken = searchParams.get("sso_token");

  useEffect(() => {
    if (!ssoToken || isLoading || isAuthenticated || attempted.current) return;

    attempted.current = true;
    setSsoInProgress(true);

    // Clean token from URL immediately
    const url = new URL(window.location.href);
    url.searchParams.delete("sso_token");
    window.history.replaceState({}, "", url.pathname + url.search);

    signIn("sso", { token: ssoToken })
      .then(() => {
        navigate("/dashboard", { replace: true });
      })
      .catch((err: Error) => {
        console.error("SSO login failed:", err);
        navigate("/login", { replace: true });
      })
      .finally(() => {
        setSsoInProgress(false);
      });
  }, [ssoToken, isLoading, isAuthenticated, signIn, navigate]);

  if (ssoInProgress || (ssoToken && !isAuthenticated && !attempted.current)) {
    return (
      <div className="flex h-screen items-center justify-center">
        <div className="flex flex-col items-center gap-3">
          <Loader2 className="size-8 animate-spin text-muted-foreground" />
          <p className="text-sm text-muted-foreground">Signing you in...</p>
        </div>
      </div>
    );
  }

  return <Outlet />;
}
