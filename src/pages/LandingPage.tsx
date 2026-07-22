import { useConvexAuth } from "convex/react";
import {
  ArrowRight,
  Check,
  Shield,
  ShieldCheck,
  Flame,
  Bug,
  Activity,
} from "lucide-react";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";

export function LandingPage() {
  const { isAuthenticated, isLoading } = useConvexAuth();

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <section className="relative flex-1 flex flex-col items-center justify-center px-4 py-16 md:py-24">
        <div className="absolute inset-0 -z-10 overflow-hidden">
          <div className="absolute inset-0 bg-[linear-gradient(to_right,hsl(var(--border))_1px,transparent_1px),linear-gradient(to_bottom,hsl(var(--border))_1px,transparent_1px)] bg-[size:4rem_4rem] [mask-image:radial-gradient(ellipse_80%_50%_at_50%_0%,#000_70%,transparent_100%)] opacity-40" />
        </div>

        <div className="max-w-5xl mx-auto text-center space-y-6">
          <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border bg-red-50 dark:bg-red-950/30 text-xs font-medium text-red-700 dark:text-red-400 border-red-200 dark:border-red-800">
            <Shield className="size-3" />
            Site Security Dashboard
          </div>

          <h1 className="text-4xl sm:text-5xl md:text-6xl lg:text-7xl font-bold tracking-tight leading-[1.1]">
            WordPress
            <br />
            <span className="text-transparent bg-clip-text bg-gradient-to-r from-red-600 via-red-500 to-orange-500">
              Security Manager
            </span>
          </h1>

          <p className="text-base md:text-lg text-muted-foreground max-w-xl mx-auto leading-relaxed">
            Monitor security posture across all your production WordPress sites.
            Track firewalls, malware scanners, plugin updates, and Wordfence status at a glance.
          </p>

          {!isAuthenticated && !isLoading && (
            <div className="flex flex-col sm:flex-row gap-3 justify-center pt-2">
              <Button size="lg" className="text-base h-11 px-6 bg-red-600 hover:bg-red-700" asChild>
                <Link to="/signup">
                  Get Started
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
              <Button
                size="lg"
                variant="outline"
                className="text-base h-11 px-6"
                asChild
              >
                <Link to="/login">Sign In</Link>
              </Button>
            </div>
          )}
          {isAuthenticated && (
            <div className="pt-2">
              <Button size="lg" className="text-base h-11 px-6 bg-red-600 hover:bg-red-700" asChild>
                <Link to="/dashboard">
                  Go to Dashboard
                  <ArrowRight className="size-4" />
                </Link>
              </Button>
            </div>
          )}

          <div className="flex items-center justify-center gap-6 pt-4 text-sm text-muted-foreground">
            <div className="flex items-center gap-1.5">
              <Check className="size-4 text-emerald-500" />
              <span>Security scoring</span>
            </div>
            <div className="flex items-center gap-1.5">
              <Check className="size-4 text-emerald-500" />
              <span>Plugin monitoring</span>
            </div>
            <div className="hidden sm:flex items-center gap-1.5">
              <Check className="size-4 text-emerald-500" />
              <span>Wordfence integration</span>
            </div>
          </div>
        </div>
      </section>

      <section className="py-20 md:py-32 border-t bg-muted/30">
        <div className="container">
          <div className="text-center mb-16">
            <p className="text-sm font-medium text-muted-foreground mb-3 tracking-wide uppercase">
              Features
            </p>
            <h2 className="text-3xl md:text-4xl font-bold tracking-tight mb-4">
              Complete Security Visibility
            </h2>
            <p className="text-muted-foreground max-w-xl mx-auto text-lg">
              Monitor every production site's security posture from a single dashboard.
            </p>
          </div>

          <div className="grid md:grid-cols-2 lg:grid-cols-3 gap-4 max-w-5xl mx-auto">
            <div className="group relative overflow-hidden rounded-2xl bg-gradient-to-br from-background to-muted/50 border p-6 md:p-8 transition-all hover:shadow-lg hover:border-foreground/20">
              <div className="absolute top-0 right-0 -mt-4 -mr-4 size-24 rounded-full bg-red-500/10 blur-2xl transition-all group-hover:bg-red-500/20" />
              <div className="relative">
                <div className="inline-flex size-11 items-center justify-center rounded-xl bg-red-500/10 mb-5">
                  <Flame className="size-5 text-red-500" />
                </div>
                <h3 className="font-semibold text-lg mb-2">Firewall Detection</h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Automatically detect Wordfence, Sucuri, Patchstack, and other firewall solutions across all sites.
                </p>
              </div>
            </div>

            <div className="group relative overflow-hidden rounded-2xl bg-gradient-to-br from-background to-muted/50 border p-6 md:p-8 transition-all hover:shadow-lg hover:border-foreground/20">
              <div className="absolute top-0 right-0 -mt-4 -mr-4 size-24 rounded-full bg-amber-500/10 blur-2xl transition-all group-hover:bg-amber-500/20" />
              <div className="relative">
                <div className="inline-flex size-11 items-center justify-center rounded-xl bg-amber-500/10 mb-5">
                  <Bug className="size-5 text-amber-500" />
                </div>
                <h3 className="font-semibold text-lg mb-2">Malware Scanning</h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  See which sites have active malware scanning and which ones need protection.
                </p>
              </div>
            </div>

            <div className="group relative overflow-hidden rounded-2xl bg-gradient-to-br from-background to-muted/50 border p-6 md:p-8 transition-all hover:shadow-lg hover:border-foreground/20">
              <div className="absolute top-0 right-0 -mt-4 -mr-4 size-24 rounded-full bg-emerald-500/10 blur-2xl transition-all group-hover:bg-emerald-500/20" />
              <div className="relative">
                <div className="inline-flex size-11 items-center justify-center rounded-xl bg-emerald-500/10 mb-5">
                  <ShieldCheck className="size-5 text-emerald-500" />
                </div>
                <h3 className="font-semibold text-lg mb-2">Security Scoring</h3>
                <p className="text-muted-foreground text-sm leading-relaxed">
                  Every site gets a letter grade (A–F) based on firewall, backup, 2FA, and plugin hygiene.
                </p>
              </div>
            </div>

            <div className="group relative overflow-hidden rounded-2xl bg-gradient-to-br from-background to-muted/50 border p-6 md:p-8 md:col-span-2 lg:col-span-2 transition-all hover:shadow-lg hover:border-foreground/20">
              <div className="absolute bottom-0 left-0 -mb-8 -ml-8 size-32 rounded-full bg-blue-500/10 blur-2xl transition-all group-hover:bg-blue-500/20" />
              <div className="relative flex flex-col md:flex-row md:items-center gap-6">
                <div className="inline-flex size-14 shrink-0 items-center justify-center rounded-2xl bg-blue-500/10">
                  <Activity className="size-7 text-blue-500" />
                </div>
                <div>
                  <h3 className="font-semibold text-lg mb-2">
                    Plugin Update Monitoring
                  </h3>
                  <p className="text-muted-foreground text-sm leading-relaxed">
                    Track outdated plugins across all sites. Outdated plugins are one of the #1 WordPress attack vectors.
                    See at a glance which sites need attention.
                  </p>
                </div>
              </div>
            </div>

            <div className="group relative overflow-hidden rounded-2xl bg-red-600 text-white p-6 md:p-8 transition-all hover:shadow-lg">
              <div className="relative">
                <h3 className="font-semibold text-lg mb-2">Start scanning</h3>
                <p className="text-white/80 text-sm leading-relaxed mb-4">
                  Connect your Rocket.net account and scan all sites in minutes.
                </p>
                <Button
                  size="sm"
                  variant="secondary"
                  className="bg-white text-red-600 hover:bg-white/90"
                  asChild
                >
                  <Link to="/signup">
                    Get Started
                    <ArrowRight className="size-4" />
                  </Link>
                </Button>
              </div>
            </div>
          </div>
        </div>
      </section>
    </div>
  );
}
