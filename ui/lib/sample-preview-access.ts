/**
 * Whether tenants without a completed scan see sample data on their pages.
 * Self-hosted deployments never show it; the Prowler Cloud overlay replaces
 * this body with its feature-flag lookup.
 */
export const isSamplePreviewEnabled = (): Promise<boolean> =>
  Promise.resolve(false);
