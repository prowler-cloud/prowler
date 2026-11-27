/**
 * Whether the current tenant's plan leaves AI Security locked. Self-hosted
 * deployments never lock it; the Prowler Cloud overlay replaces this body
 * with its billing lookup.
 */
export const isAiSecurityLocked = (): Promise<boolean> =>
  Promise.resolve(false);
