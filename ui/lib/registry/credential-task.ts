import type { RegistryCredentialStatus } from "@/types/registry";

/**
 * Watched-task kind for Registry API key validation. Metadata retains only
 * whether a credential was already configured; the submitted key is write-only
 * and must never reach the persisted watcher record.
 */
export const REGISTRY_CREDENTIAL_TASK_KIND = "registry-credential-validation";

export const isActiveRegistryCredential = (
  credential: RegistryCredentialStatus | null,
) =>
  Boolean(
    credential?.configured &&
      credential.isValid &&
      !credential.validationPending,
  );

export const isRegistryCredentialTaskSuccessful = (result: unknown): boolean =>
  typeof result === "object" &&
  result !== null &&
  "stored" in result &&
  result.stored === true &&
  "error" in result &&
  result.error === null;

/** Translate known rejection reasons without reflecting server payloads or secrets. */
export function getRegistryCredentialFailureMessage(
  result: unknown,
): string | undefined {
  if (
    typeof result !== "object" ||
    result === null ||
    !("error" in result) ||
    typeof result.error !== "string"
  )
    return;
  const error = result.error.toLowerCase();
  if (error.includes("http 401"))
    return "The configured Registry rejected this key (HTTP 401). Check that the key belongs to this Registry environment and is still active.";
  if (error.includes("organization keys are not supported"))
    return "Use a customer download key for the official Registry. Organization upload keys cannot connect this workspace.";
  if (error.includes("download scope"))
    return "This key needs a download scope. Create a download key in Registry and try again.";
  if (error.includes("customer accounts disabled"))
    return "Customer accounts are disabled on the configured Registry. Contact its administrator.";
}
