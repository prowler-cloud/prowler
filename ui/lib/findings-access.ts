/** Finding groups a locked tenant can read on /findings; the rest of the page renders blurred. */
export const FINDINGS_PREVIEW_ROW_LIMIT = 10;

/**
 * Whether the current tenant only previews the most critical finding groups.
 * Self-hosted deployments never lock the list; the Prowler Cloud overlay
 * replaces this body with its billing and feature-flag lookup.
 */
export const isFindingsPreviewLocked = (): Promise<boolean> =>
  Promise.resolve(false);
