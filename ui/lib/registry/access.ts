export const REGISTRY_ACCESS = {
  ELIGIBLE: "eligible",
  INELIGIBLE: "ineligible",
  UNKNOWN: "unknown",
} as const;

export type RegistryAccessStatus =
  (typeof REGISTRY_ACCESS)[keyof typeof REGISTRY_ACCESS];

export interface RegistryAccessResult {
  status: RegistryAccessStatus;
}

export const isRegistryEligible = (
  cloudEnabled: unknown,
  registryEnabled: unknown,
  manageRegistry: unknown,
) =>
  cloudEnabled === true && registryEnabled === true && manageRegistry === true;
