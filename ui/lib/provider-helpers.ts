import {
  checkConnectionProvider,
  getProvider,
} from "@/actions/providers/providers";
import {
  CONNECTION_CHECK_STATUS,
  type ConnectionCheckStatus,
  ProviderEntity,
  ProviderProps,
  ProvidersApiResponse,
  ProviderType,
} from "@/types/providers";

import { checkTaskStatus, TASK_STATUS_MAX_RETRIES_ERROR } from "./helper";

// Re-exported so callers that only need the status enum (e.g.
// `org-account-selection.utils.ts` and its tests) can import it from
// `@/types/providers` directly, without pulling in this module's server-action
// dependencies.
export { CONNECTION_CHECK_STATUS };
export type { ConnectionCheckStatus };

export const extractProviderUIDs = (
  providersData: ProvidersApiResponse,
): string[] => {
  if (!providersData?.data) return [];

  return Array.from(
    new Set(
      providersData.data
        .map((provider: ProviderProps) => provider.attributes?.uid)
        .filter(Boolean),
    ),
  );
};

export const extractProviderIds = (
  providersData: ProvidersApiResponse,
): string[] => {
  if (!providersData?.data) return [];

  return providersData.data
    .map((provider: ProviderProps) => provider.id)
    .filter(Boolean);
};

export const createProviderDetailsMapping = (
  providerUIDs: string[],
  providersData: ProvidersApiResponse,
): Array<{ [uid: string]: ProviderEntity }> => {
  if (!providersData?.data) return [];

  return providerUIDs.map((uid) => {
    const provider = providersData.data.find(
      (p: { attributes: { uid: string } }) => p.attributes?.uid === uid,
    );

    return {
      [uid]: {
        provider: provider?.attributes?.provider ?? "",
        uid: uid,
        alias: provider?.attributes?.alias ?? null,
      },
    };
  });
};

export const createProviderDetailsMappingById = (
  providerIds: string[],
  providersData: ProvidersApiResponse,
): Array<{ [id: string]: ProviderEntity }> => {
  if (!providersData?.data) return [];

  return providerIds.map((id) => {
    const provider = providersData.data.find((p: ProviderProps) => p.id === id);

    return {
      [id]: {
        provider: provider?.attributes?.provider ?? "",
        uid: provider?.attributes?.uid || "",
        alias: provider?.attributes?.alias ?? null,
      },
    };
  });
};

// Helper function to determine which form type to show
export type ProviderFormType =
  | "selector"
  | "credentials"
  | "role"
  | "service-account"
  | null;

export const getProviderFormType = (
  providerType: ProviderType,
  via?: string,
): ProviderFormType => {
  // Providers that need credential type selection
  const needsSelector = [
    "aws",
    "gcp",
    "github",
    "m365",
    "alibabacloud",
    "cloudflare",
  ].includes(providerType);

  // Show selector if no via parameter and provider needs it
  if (needsSelector && !via) {
    return "selector";
  }

  // AWS specific forms
  if (providerType === "aws") {
    if (via === "role") return "role";
    if (via === "credentials") return "credentials";
  }

  // GCP specific forms
  if (providerType === "gcp") {
    if (via === "service-account") return "service-account";
    if (via === "credentials") return "credentials";
  }

  // GitHub credential types
  if (
    providerType === "github" &&
    ["personal_access_token", "oauth_app", "github_app"].includes(via || "")
  ) {
    return "credentials";
  }

  // M365 credential types
  if (
    providerType === "m365" &&
    ["app_client_secret", "app_certificate"].includes(via || "")
  ) {
    return "credentials";
  }

  // AlibabaCloud specific forms
  if (providerType === "alibabacloud") {
    if (via === "role") return "role";
    if (via === "credentials") return "credentials";
  }

  // Cloudflare credential types
  if (
    providerType === "cloudflare" &&
    ["api_token", "api_key"].includes(via || "")
  ) {
    return "credentials";
  }

  // Other providers go directly to credentials form
  if (!needsSelector) {
    return "credentials";
  }

  return null;
};

// Helper to check if back button should be shown based on via parameter
export const requiresBackButton = (via?: string | null): boolean => {
  if (!via) return false;

  const validViaTypes = [
    "credentials",
    "role",
    "service-account",
    "personal_access_token",
    "oauth_app",
    "github_app",
    "app_client_secret",
    "app_certificate",
    "api_token",
    "api_key",
  ];
  // Note: "role" is already included for AWS, now also used by AlibabaCloud
  // "api_token" and "api_key" are used by Cloudflare

  return validViaTypes.includes(via);
};

export interface TestConnectionResult {
  status: ConnectionCheckStatus;
  error: string | null;
}

/**
 * The `provider-connection-check` Celery task has a 120s hard time limit
 * (api/src/backend/config/celery.py `task_annotations`). Poll long enough to
 * cover a full run plus queueing/network slack, instead of the generic 30s
 * default, which cuts the wait off well before the backend gives up.
 */
export const PROVIDER_CONNECTION_CHECK_TASK_TIME_LIMIT_MS = 120_000;
const PROVIDER_CONNECTION_CHECK_POLL_BUFFER_MS = 30_000;
export const PROVIDER_CONNECTION_CHECK_POLL_DELAY_MS = 1_500;
export const PROVIDER_CONNECTION_CHECK_MAX_RETRIES = Math.ceil(
  (PROVIDER_CONNECTION_CHECK_TASK_TIME_LIMIT_MS +
    PROVIDER_CONNECTION_CHECK_POLL_BUFFER_MS) /
    PROVIDER_CONNECTION_CHECK_POLL_DELAY_MS,
);

const CONNECTION_NOT_CONFIRMED_MESSAGE =
  "Connection was not confirmed. Test the connection again.";
const CONNECTION_STILL_RUNNING_MESSAGE =
  "The connection test is still running. Refresh in a moment to see the result.";

/**
 * Reads a provider's current `connection.last_checked_at`, to be captured
 * *before* a connection check is dispatched for it. Passed on to
 * `resolveProviderConnectionState` as the value a later read is compared against
 * -- see that function for why the comparison is by value, not by clock.
 *
 * `undefined` means the read failed (network error, provider not found) and is
 * distinct from `null` ("no prior check exists"): `resolveProviderConnectionState`
 * treats an unknown baseline as impossible to clear, never as an implicit change.
 */
export async function captureConnectionBaseline(
  providerId: string,
): Promise<string | null | undefined> {
  const formData = new FormData();
  formData.append("id", providerId);

  const providerResponse = await getProvider(formData);
  if (!providerResponse?.data) {
    return undefined;
  }

  return providerResponse.data.attributes?.connection?.last_checked_at ?? null;
}

/**
 * Re-reads a provider's persisted connection state from the API. Used when a
 * connection-check wait is exhausted: the backend task may still be running (or
 * may already have finished after the UI stopped waiting on it), so this reports
 * whatever the provider record currently says instead of a flat error.
 *
 * The stored `connection` is the result of the *last check that finished*, not
 * necessarily the one this call is following up on -- e.g. a provider was
 * connected, the user changed its credentials, and the new check is still
 * running past the wait. `baseline` -- the provider's `last_checked_at` captured
 * (via {@link captureConnectionBaseline}) before this check was dispatched --
 * guards against reporting that stale result as current: the stored state is
 * only trusted once `last_checked_at` has changed from it.
 *
 * This compares the two values directly rather than comparing timestamps, so it
 * holds even in deployments whose clocks are not synchronised: `last_checked_at`
 * is written by the server, but the previous check used a wait deadline taken
 * from the browser's clock, and a browser clock that drifts from the server's
 * could make an older result look newer than the check, or a finished check look
 * like it is still pending.
 */
export async function resolveProviderConnectionState(
  providerId: string,
  baseline: string | null | undefined,
): Promise<TestConnectionResult> {
  const formData = new FormData();
  formData.append("id", providerId);

  const providerResponse = await getProvider(formData);
  const connection = providerResponse?.data?.attributes?.connection;
  const lastCheckedAt = connection?.last_checked_at;

  // An unknown baseline (the pre-dispatch read failed) can never be cleared --
  // there is nothing to compare against, so the result cannot be trusted yet.
  const isCurrent =
    baseline !== undefined && !!lastCheckedAt && lastCheckedAt !== baseline;

  if (!isCurrent) {
    // No persisted result yet, or it predates this check -- the backend task
    // may still be running.
    return {
      status: CONNECTION_CHECK_STATUS.PENDING,
      error: CONNECTION_STILL_RUNNING_MESSAGE,
    };
  }

  if (connection?.connected === true) {
    return { status: CONNECTION_CHECK_STATUS.SUCCESS, error: null };
  }

  if (connection?.connected === false) {
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: CONNECTION_NOT_CONFIRMED_MESSAGE,
    };
  }

  // Current per its timestamp, but `connected` is null -- treat the same as
  // still pending rather than guessing a pass or fail.
  return {
    status: CONNECTION_CHECK_STATUS.PENDING,
    error: CONNECTION_STILL_RUNNING_MESSAGE,
  };
}

/**
 * Tests a provider's connection end-to-end: submits the task, polls until
 * completion, and returns the real connection result.
 *
 * Single-provider paths only (the wizard and the table's per-row action); a batch
 * goes through `startProviderConnectionChecks`, which fans out server-side.
 */
export async function testProviderConnection(
  providerId: string,
): Promise<TestConnectionResult> {
  // Captured before the check is dispatched, so any `last_checked_at` this check
  // eventually writes is guaranteed to differ from it.
  const baseline = await captureConnectionBaseline(providerId);

  const formData = new FormData();
  formData.append("providerId", providerId);

  const data = await checkConnectionProvider(formData);

  if (data?.errors && data.errors.length > 0) {
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: data.errors[0]?.detail ?? "Unknown error",
    };
  }

  const taskId = data?.data?.id;
  if (!taskId) {
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: "No task ID returned",
    };
  }

  const taskResult = await checkTaskStatus(
    taskId,
    PROVIDER_CONNECTION_CHECK_MAX_RETRIES,
    PROVIDER_CONNECTION_CHECK_POLL_DELAY_MS,
  );

  if (!taskResult.completed) {
    if (taskResult.error === TASK_STATUS_MAX_RETRIES_ERROR) {
      return resolveProviderConnectionState(providerId, baseline);
    }
    return {
      status: CONNECTION_CHECK_STATUS.FAILED,
      error: taskResult.error ?? "Connection test timed out",
    };
  }

  // Task completion alone does not confirm that the credentials connected.
  const result = taskResult.task?.data?.attributes?.result;
  const connected = result?.connected === true;

  return {
    status: connected
      ? CONNECTION_CHECK_STATUS.SUCCESS
      : CONNECTION_CHECK_STATUS.FAILED,
    error: connected ? null : result?.error || CONNECTION_NOT_CONFIRMED_MESSAGE,
  };
}
