export const REGISTRY_ACCESS = {
  ELIGIBLE: "eligible",
  INELIGIBLE: "ineligible",
  UNKNOWN: "unknown",
} as const;

export type RegistryAccessStatus =
  (typeof REGISTRY_ACCESS)[keyof typeof REGISTRY_ACCESS];

export const REGISTRY_ACCESS_LEASE_MS = 30_000;

export type RegistryAccessResult =
  | {
      status: typeof REGISTRY_ACCESS.ELIGIBLE;
      leaseDurationMs: typeof REGISTRY_ACCESS_LEASE_MS;
    }
  | { status: typeof REGISTRY_ACCESS.INELIGIBLE }
  | { status: typeof REGISTRY_ACCESS.UNKNOWN };

export const isRegistryEligible = (
  cloudEnabled: unknown,
  registryEnabled: unknown,
  manageRegistry: unknown,
) =>
  cloudEnabled === true && registryEnabled === true && manageRegistry === true;

export const registryAccessResult = (
  status: RegistryAccessStatus,
): RegistryAccessResult =>
  status === REGISTRY_ACCESS.ELIGIBLE
    ? { status, leaseDurationMs: REGISTRY_ACCESS_LEASE_MS }
    : { status };
