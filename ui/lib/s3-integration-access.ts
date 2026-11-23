export const S3_INTEGRATION_LOCKED_ERROR =
  "Amazon S3 integrations require an active subscription.";

/**
 * Whether the current tenant must upgrade before adding Amazon S3 integrations.
 * Self-hosted deployments never lock it; the Prowler Cloud overlay replaces
 * this body with its billing lookup.
 */
export const isS3IntegrationLocked = (): Promise<boolean> =>
  Promise.resolve(false);
