import {
  refreshRegistryCredential,
  refreshRegistryCollections,
} from "@/actions/registry/registry";
import { toast } from "@/components/shadcn/toast";
import {
  getRegistryCredentialFailureMessage,
  isActiveRegistryCredential,
  isRegistryCredentialTaskSuccessful,
} from "@/lib/registry/credential-task";
import {
  TASK_WATCHER_STATUS,
  type TaskTrackingResult,
} from "@/store/task-watcher/store";
import {
  REGISTRY_CATALOG,
  REGISTRY_CREDENTIAL_ACTION,
  REGISTRY_CREDENTIAL_READ,
  REGISTRY_FAILURE,
  type RegistryCredentialReadResult,
  type RegistryCredentialStatus,
  type RegistryCollectionsResult,
} from "@/types/registry";

export type RegistryCredentialValidationOutcome =
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.CONNECTED;
      collections: Extract<RegistryCollectionsResult, { status: "complete" }>;
      credential: RegistryCredentialStatus;
    }
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.PENDING;
      credential?: RegistryCredentialStatus;
    }
  | {
      status: typeof REGISTRY_CREDENTIAL_ACTION.INVALID;
      credential: RegistryCredentialStatus;
      message?: string;
    }
  | { status: typeof REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED }
  | { status: typeof REGISTRY_FAILURE.ACCESS_DENIED }
  | { status: typeof REGISTRY_FAILURE.ERROR; message?: string };

export const REGISTRY_CREDENTIAL_CHANGED = "registry-credential-changed";

async function confirmCredential(
  tracked: TaskTrackingResult,
  priorConfigured: boolean,
): Promise<RegistryCredentialValidationOutcome> {
  let read: RegistryCredentialReadResult;
  try {
    read = await refreshRegistryCredential();
  } catch {
    return { status: REGISTRY_FAILURE.ERROR };
  }
  if (read.status === REGISTRY_FAILURE.ACCESS_DENIED) {
    return { status: REGISTRY_FAILURE.ACCESS_DENIED };
  }
  if (read.status !== REGISTRY_CREDENTIAL_READ.STATUS) {
    return { status: REGISTRY_FAILURE.ERROR };
  }

  const { credential } = read;
  // Both the submitted task and the authoritative credential must confirm success.
  if (
    isActiveRegistryCredential(credential) &&
    tracked.status === TASK_WATCHER_STATUS.READY &&
    isRegistryCredentialTaskSuccessful(tracked.result)
  ) {
    const collections = await refreshRegistryCollections().catch(() => null);
    if (collections?.status === REGISTRY_FAILURE.ACCESS_DENIED)
      return { status: REGISTRY_FAILURE.ACCESS_DENIED };
    if (collections?.status !== REGISTRY_CATALOG.COMPLETE)
      return {
        status: REGISTRY_FAILURE.ERROR,
        message: "Registry collections could not be loaded. Try again.",
      };
    return {
      status: REGISTRY_CREDENTIAL_ACTION.CONNECTED,
      credential,
      collections,
    };
  }
  if (credential.validationPending) {
    return { status: REGISTRY_CREDENTIAL_ACTION.PENDING, credential };
  }
  // An unsettled watch has not judged the key; report it still pending
  // rather than invalid or a failed replacement.
  if (tracked.status === TASK_WATCHER_STATUS.PENDING) {
    return { status: REGISTRY_CREDENTIAL_ACTION.PENDING, credential };
  }
  if (priorConfigured) {
    return { status: REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED };
  }
  const message = getRegistryCredentialFailureMessage(tracked.result);
  return {
    status: REGISTRY_CREDENTIAL_ACTION.INVALID,
    credential,
    ...(message ? { message } : {}),
  };
}

export function credentialOutcomeMessage(
  result: RegistryCredentialValidationOutcome,
): string {
  if (result.status === REGISTRY_CREDENTIAL_ACTION.PENDING)
    return "Registry key validation is taking longer than expected. Try again.";
  if (result.status === REGISTRY_CREDENTIAL_ACTION.REPLACEMENT_FAILED)
    return "Registry key validation failed. Existing access is unchanged.";
  if (result.status === REGISTRY_CREDENTIAL_ACTION.INVALID)
    return (
      result.message ?? "This Registry key is invalid. Check it and try again."
    );
  return (
    (result.status === REGISTRY_FAILURE.ERROR && result.message) ||
    "Registry key validation could not be completed. Try again."
  );
}

/** Shared by the active operation and the watcher after a document reload. */
export async function completeRegistryCredentialValidation(
  tracked: TaskTrackingResult,
  priorConfigured: boolean,
  notify = true,
): Promise<RegistryCredentialValidationOutcome> {
  const outcome = await confirmCredential(tracked, priorConfigured);
  if (notify) {
    if (outcome.status === REGISTRY_CREDENTIAL_ACTION.CONNECTED) {
      toast({ title: "Registry connected" });
    } else if (outcome.status !== REGISTRY_FAILURE.ACCESS_DENIED) {
      toast({
        variant: "destructive",
        title: "Registry key validation failed",
        description: credentialOutcomeMessage(outcome),
      });
    }
    window.dispatchEvent(
      new CustomEvent(REGISTRY_CREDENTIAL_CHANGED, { detail: outcome }),
    );
  }
  return outcome;
}
