/**
 * Scheduled cron jobs for the Security Manager.
 *
 * - Daily vulnerability scan at 6:00 AM UTC (2:00 AM ET)
 *   Scans all sites' plugins against WPVulnerability.net CVE data
 *   and sends Slack alerts for any new findings.
 */
import { cronJobs } from "convex/server";
import { api } from "./_generated/api";

const crons = cronJobs();

// Run vulnerability scan daily at 6 AM UTC (2 AM ET)
// The `notify: true` flag tells scanAllSites to send Slack alerts for new vulns
crons.daily(
  "daily-vuln-scan",
  { hourUTC: 6, minuteUTC: 0 },
  api.vulnScan.scanAllSites,
  { notify: true },
);

export default crons;
