import { Navigate, Route, Routes } from "react-router-dom";
import { AppLayout } from "./components/AppLayout";
import ErrorBoundary from "./components/ErrorBoundary";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { PublicLayout } from "./components/PublicLayout";
import { PublicOnlyRoute } from "./components/PublicOnlyRoute";
import { SSOGate } from "./components/SSOGate";
import { Toaster } from "./components/ui/sonner";
import { ThemeProvider } from "./contexts/ThemeContext";
import {
  LandingPage,
  LoginPage,
  SettingsPage,
  SignupPage,
} from "./pages";
import DashboardPage from "./pages/DashboardPage";
import SiteDetailPage from "./pages/SiteDetailPage";
import ActivityPage from "./pages/ActivityPage";
import VulnerabilitiesPage from "./pages/VulnerabilitiesPage";
import ServersPage from "./pages/ServersPage";

function App() {
  return (
    <ErrorBoundary>
      <ThemeProvider defaultTheme="system" switchable>
        <Toaster />
        <Routes>
          {/* SSO Gate wraps everything to intercept ?sso_token= */}
          <Route element={<SSOGate />}>
            <Route element={<PublicLayout />}>
              <Route path="/" element={<LandingPage />} />
              <Route element={<PublicOnlyRoute />}>
                <Route path="/login" element={<LoginPage />} />
                <Route path="/signup" element={<SignupPage />} />
              </Route>
            </Route>

            <Route element={<ProtectedRoute />}>
              <Route element={<AppLayout />}>
                <Route path="/dashboard" element={<DashboardPage />} />
                <Route path="/site/:siteId" element={<SiteDetailPage />} />
                <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
                <Route path="/activity" element={<ActivityPage />} />
                <Route path="/servers" element={<ServersPage />} />
                <Route path="/settings" element={<SettingsPage />} />
              </Route>
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Route>
        </Routes>
      </ThemeProvider>
    </ErrorBoundary>
  );
}

export default App;
