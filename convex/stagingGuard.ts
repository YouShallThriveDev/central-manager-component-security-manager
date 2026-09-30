/**
 * Staging-only write guard. Pure (no Convex imports) so it can be tested
 * directly. Every Rocket.net write in stagingFix.ts goes through
 * assertStagingTarget; production sites must never be written to.
 */

export const STAGING_SUFFIXES = ["-staging.wpdns.site", ".staging.wpdns.site"];

export const isStagingDomain = (domain: unknown): boolean =>
  typeof domain === "string" &&
  STAGING_SUFFIXES.some(s => domain.toLowerCase().endsWith(s));

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
