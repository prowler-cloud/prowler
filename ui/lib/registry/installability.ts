const REGISTRY_NOT_INSTALLABLE_COPY = {
  checks_target_is_not_builtin:
    "Its checks are written for a provider this deployment does not ship.",
  artifact_compliance_not_supported:
    "It ships compliance frameworks as well as checks, which is not supported yet.",
  artifact_targets_no_provider:
    "It ships checks but names no provider to extend.",
  artifact_defines_nothing_usable: "It brings neither a provider nor checks.",
  artifact_ships_with_prowler:
    "Its code is already inside Prowler. Nothing to install.",
} as const;

const REGISTRY_NOT_INSTALLABLE_FALLBACK =
  "This artifact cannot be installed in this deployment.";

/** Explains the API's refusal code; codes it adds later get the fallback. */
export function getRegistryNotInstallableMessage(reason?: string): string {
  return reason && Object.hasOwn(REGISTRY_NOT_INSTALLABLE_COPY, reason)
    ? REGISTRY_NOT_INSTALLABLE_COPY[
        reason as keyof typeof REGISTRY_NOT_INSTALLABLE_COPY
      ]
    : REGISTRY_NOT_INSTALLABLE_FALLBACK;
}
