/** The API's codes for why an artifact cannot be installed. */
export const REGISTRY_NOT_INSTALLABLE_REASON = {
  ACCESS_REQUIRED: "access_required",
  ARTIFACT_TARGETS_NO_PROVIDER: "artifact_targets_no_provider",
  ARTIFACT_DEFINES_NOTHING_USABLE: "artifact_defines_nothing_usable",
  ARTIFACT_SHIPS_WITH_PROWLER: "artifact_ships_with_prowler",
  PROWLER_UPGRADE_REQUIRED: "prowler_upgrade_required",
  DEPENDENCY_ACCESS_REQUIRED: "dependency_access_required",
} as const;

type RegistryNotInstallableReason =
  (typeof REGISTRY_NOT_INSTALLABLE_REASON)[keyof typeof REGISTRY_NOT_INSTALLABLE_REASON];

const REGISTRY_NOT_INSTALLABLE_COPY: Record<
  RegistryNotInstallableReason,
  string
> = {
  [REGISTRY_NOT_INSTALLABLE_REASON.ACCESS_REQUIRED]:
    "Needs approved access in the Prowler Registry. Once approved, it installs with that account's Registry API key.",
  [REGISTRY_NOT_INSTALLABLE_REASON.ARTIFACT_TARGETS_NO_PROVIDER]:
    "It ships checks but names no provider to extend.",
  [REGISTRY_NOT_INSTALLABLE_REASON.ARTIFACT_DEFINES_NOTHING_USABLE]:
    "It brings neither a provider nor checks.",
  [REGISTRY_NOT_INSTALLABLE_REASON.ARTIFACT_SHIPS_WITH_PROWLER]:
    "Its code is already inside Prowler. Nothing to install.",
  [REGISTRY_NOT_INSTALLABLE_REASON.PROWLER_UPGRADE_REQUIRED]:
    "It needs a newer Prowler version than this deployment runs. It will install once the deployment is upgraded.",
  [REGISTRY_NOT_INSTALLABLE_REASON.DEPENDENCY_ACCESS_REQUIRED]:
    "It depends on another Prowler Registry artifact that your Registry API key cannot install.",
};

const REGISTRY_NOT_INSTALLABLE_FALLBACK =
  "This artifact cannot be installed in this deployment.";

/** Explains the API's refusal code; codes it adds later get the fallback. */
export function getRegistryNotInstallableMessage(
  reason?: string,
  fallback: string = REGISTRY_NOT_INSTALLABLE_FALLBACK,
): string {
  return reason && Object.hasOwn(REGISTRY_NOT_INSTALLABLE_COPY, reason)
    ? REGISTRY_NOT_INSTALLABLE_COPY[reason as RegistryNotInstallableReason]
    : fallback;
}
