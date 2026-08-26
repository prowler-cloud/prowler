import type { RegistryCredentialStatus } from "@/types/registry";

/**
 * Watched-task kind for Registry API key validation. The task watcher meta for
 * this kind is always empty: the submitted key is write-only and must never
 * reach the persisted watcher record.
 */
export const REGISTRY_CREDENTIAL_TASK_KIND = "registry-credential-validation";

export const isActiveRegistryCredential = (
  credential: RegistryCredentialStatus,
) =>
  credential.configured && credential.isValid && !credential.validationPending;
