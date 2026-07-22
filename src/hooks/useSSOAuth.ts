/**
 * Auto-login hook for SSO tokens from Central Manager.
 * Checks URL for ?sso_token=... and signs in automatically.
 */
import { useAuthActions } from "@convex-dev/auth/react";
import { useConvexAuth } from "convex/react";
import { useEffect, useRef } from "react";
import { useSearchParams, useNavigate } from "react-router-dom";

export function useSSOAuth() {
  const { signIn } = useAuthActions();
  const { isAuthenticated, isLoading } = useConvexAuth();
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const attempted = useRef(false);

  useEffect(() => {
    const ssoToken = searchParams.get("sso_token");
    if (!ssoToken || isLoading || isAuthenticated || attempted.current) return;

    attempted.current = true;

    // Clean token from URL immediately
    const url = new URL(window.location.href);
    url.searchParams.delete("sso_token");
    window.history.replaceState({}, "", url.pathname + url.search);

    // Sign in via SSO provider
    signIn("sso", { token: ssoToken })
      .then(() => {
        navigate("/dashboard", { replace: true });
      })
      .catch((err: Error) => {
        console.error("SSO login failed:", err);
        navigate("/login", { replace: true });
      });
  }, [searchParams, isLoading, isAuthenticated, signIn, navigate]);
}
