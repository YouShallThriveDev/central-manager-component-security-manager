/**
 * Staging-only write guard. Pure (no Convex imports) so it can be tested
 * directly. Every Rocket.net write in stagingFix.ts goes through
 * assertStagingTarget; production sites must never be written to.
 */

// Rocket.net-owned hosting domains that staging copies are served from.
// Observed: "<id>-staging.wpdns.site" (most) and "<id>-staging.onrocket.site".
const STAGING_HOSTS = ["wpdns.site", "onrocket.site"];

export const STAGING_SUFFIXES = STAGING_HOSTS.flatMap(h => [
  `-staging.${h}`,
  `.staging.${h}`,
]);

// Strict suffix match on a Rocket-owned host with a non-empty label before it,
// so look-alikes such as "x-staging.onrocket.site.attacker.com" are rejected.
export const isStagingDomain = (domain: unknown): boolean => {
  if (typeof domain !== "string") return false;
  const d = domain.trim().toLowerCase();
  return STAGING_SUFFIXES.some(
    s => d.length > s.length && d.endsWith(s) && !d.startsWith("."),
  );
};

export type StagingTarget = {
  // Live GET /sites/{id} of the site about to be written to
  id: unknown;
  domain: unknown;
  production: unknown; // staging sites carry their parent's id here
};

export type StagingParent = {
  rocketSiteId: number;
  stagingSiteId?: number;
};

export function assertStagingTarget(
  target: StagingTarget,
  parent: StagingParent,
): number {
  const fail = (why: string): never => {
    throw new Error(`Refusing Rocket.net write: ${why}`);
  };
  if (!parent.stagingSiteId) fail("parent site has no staging copy on record");
  if (typeof target.id !== "number" || target.id <= 0)
    fail("target site id is missing");
  if (target.id === parent.rocketSiteId) fail("target is the production site");
  if (target.id !== parent.stagingSiteId) {
    fail(
      `target ${target.id} is not the stored staging id ${parent.stagingSiteId}`,
    );
  }
  if (!isStagingDomain(target.domain))
    fail(`target domain "${target.domain}" is not a staging domain`);
  if (target.production !== parent.rocketSiteId) {
    fail(
      `target does not report production site ${parent.rocketSiteId} as its parent`,
    );
  }
  return target.id as number;
}
