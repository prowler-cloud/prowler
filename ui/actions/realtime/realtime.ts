"use server";

import { z } from "zod";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import {
  realtimeCostAnomalySchema,
  realtimeCredentialSchema,
  realtimeFeedSchema,
  realtimeNotificationsSchema,
  realtimePolicyPatchSchema,
  realtimePolicySchema,
} from "@/lib/realtime/policy-schema";
import { handleApiResponse } from "@/lib/server-actions-helper";
import type {
  RealtimeAction,
  RealtimeApiDocument,
  RealtimeApiError,
  RealtimeAnomalyPayload,
  RealtimeCostAnomalySettings,
  RealtimeCredential,
  RealtimeCredentialInput,
  RealtimeDemoKind,
  RealtimeDemoPayloads,
  RealtimeDetection,
  RealtimeEvent,
  RealtimeFailure,
  RealtimeFeed,
  RealtimeFeedInput,
  RealtimeFramework,
  RealtimeHealth,
  RealtimeInsightKind,
  RealtimeInsightPayloads,
  RealtimeNotifications,
  RealtimeNotificationTargets,
  RealtimePage,
  RealtimePolicy,
  RealtimePolicyInput,
  RealtimeRemediation,
  RealtimeResult,
  RealtimeSetupPayload,
} from "@/types/realtime";
import {
  REALTIME_DEMO_LIST_KIND,
  REALTIME_INSIGHT_KIND,
} from "@/types/realtime";

import {
  resourcesOf,
  toAction,
  toCredential,
  toDetection,
  toEvent,
  toFeed,
  toFieldErrors,
  toFramework,
  toHealth,
  toDemoPayload,
  toInsightPayload,
  toNotificationTargets,
  toPage,
  toPolicy,
  toRemediation,
  toRequestBody,
  toSetup,
} from "./realtime.adapter";

const REALTIME_URL = `${apiBaseUrl}/realtime`;
const UNREACHABLE =
  "Prowler could not reach the Prowler Realtime service. Try again.";
const INVALID_PROVIDER = "Select an AWS provider first.";
const MAX_EVENTS = 500;
const DEFAULT_PAGE_SIZE = 25;

const uuid = z.uuid();
const isUuid = (value: string) => uuid.safeParse(value).success;

const fail = (
  status: number,
  error: string,
  fieldErrors?: Record<string, string>,
): RealtimeFailure => ({
  ok: false,
  status,
  error,
  ...(fieldErrors && Object.keys(fieldErrors).length ? { fieldErrors } : {}),
});

/** A schema failure as a 400: the first message, plus one per field. */
const invalid = (error: z.ZodError, fallback: string): RealtimeFailure => {
  const fieldErrors: Record<string, string> = {};
  error.issues.forEach((issue) => {
    const field = String(issue.path[0] ?? "form");
    if (!fieldErrors[field]) fieldErrors[field] = issue.message;
  });
  return fail(400, error.issues[0]?.message ?? fallback, fieldErrors);
};

const detailOf = async (response: Response, fallback: string) => {
  const body = (await response.json().catch(() => undefined)) as
    | { errors?: RealtimeApiError[] }
    | undefined;
  return body?.errors?.[0]?.detail || fallback;
};

/**
 * One call to the Prowler Realtime API.
 *
 * 409 (AWS refused a revert) and 503 (data store not configured) are normal
 * answers here: they come back as a failure the panel can explain, and they
 * are not reported as server errors. Any other 5xx still goes through
 * `handleApiResponse`, which reports it.
 */
const call = async (
  path: string,
  init: { method?: string; body?: unknown; query?: URLSearchParams } = {},
): Promise<
  | { ok: true; document: RealtimeApiDocument | undefined; status: number }
  | RealtimeFailure
> => {
  try {
    const url = new URL(`${REALTIME_URL}/${path}`);
    init.query?.forEach((value, key) => url.searchParams.append(key, value));
    const response = await fetch(url.toString(), {
      method: init.method ?? "GET",
      headers: await getAuthHeaders({ contentType: init.body !== undefined }),
      body: init.body === undefined ? undefined : JSON.stringify(init.body),
      cache: "no-store",
    });

    if (response.status === 409 || response.status === 503) {
      return fail(
        response.status,
        await detailOf(
          response,
          response.status === 503
            ? "Prowler Realtime's data store is not available."
            : "AWS did not accept the change.",
        ),
      );
    }

    const body = await handleApiResponse(response);
    if (body && typeof body.error === "string" && !body.data) {
      return fail(
        Number(body.status) || response.status,
        body.error,
        toFieldErrors(body.errors),
      );
    }
    return { ok: true, document: body, status: response.status };
  } catch (error) {
    console.error("Prowler Realtime request failed:", error);
    return fail(0, UNREACHABLE);
  }
};

const withProvider = (providerId: string, extra?: Record<string, string>) => {
  const query = new URLSearchParams({ "filter[provider]": providerId });
  Object.entries(extra ?? {}).forEach(([key, value]) => query.set(key, value));
  return query;
};

// ------------------------------------------------------------------ policy

/** Create the provider's policy, or patch it when `policyId` is given. */
const writePolicy = async ({
  providerId,
  policyId,
  attributes,
  unreadable,
}: {
  providerId: string;
  policyId?: string;
  attributes: Record<string, unknown>;
  unreadable: string;
}): Promise<RealtimeResult<RealtimePolicy>> => {
  const result = policyId
    ? await call(`policies/${policyId}`, {
        method: "PATCH",
        body: toRequestBody({
          type: "realtime-policies",
          id: policyId,
          attributes,
        }),
      })
    : await call("policies", {
        method: "POST",
        body: toRequestBody({
          type: "realtime-policies",
          attributes,
          providerId,
        }),
      });
  if (!result.ok) return result;
  const [saved] = resourcesOf(result.document);
  return saved ? { ok: true, data: toPolicy(saved) } : fail(0, unreadable);
};

export const getRealtimePolicy = async (
  providerId: string,
): Promise<RealtimeResult<RealtimePolicy | null>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call("policies", { query: withProvider(providerId) });
  if (!result.ok) return result;
  const [first] = resourcesOf(result.document);
  return { ok: true, data: first ? toPolicy(first) : null };
};

/** Create the provider's policy, or update it when one already exists. */
export const saveRealtimePolicy = async ({
  providerId,
  policyId,
  policy,
}: {
  providerId: string;
  policyId?: string;
  policy: RealtimePolicyInput;
}): Promise<RealtimeResult<RealtimePolicy>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  if (policyId && !isUuid(policyId)) return fail(400, "Unknown policy.");
  const parsed = realtimePolicySchema.safeParse(policy);
  if (!parsed.success) {
    return invalid(parsed.error, "The policy is not valid.");
  }

  return writePolicy({
    providerId,
    policyId,
    attributes: parsed.data,
    unreadable: "The policy was saved but the answer was unreadable.",
  });
};

/**
 * Save only the cost anomaly settings. Updates send just those fields, so a
 * stale page cannot overwrite the rest of the policy; a provider without a
 * policy gets one created with the API's defaults (detection stays off).
 */
export const saveRealtimeCostSettings = async ({
  providerId,
  policyId,
  settings,
}: {
  providerId: string;
  policyId?: string;
  settings: RealtimeCostAnomalySettings;
}): Promise<RealtimeResult<RealtimePolicy>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  if (policyId && !isUuid(policyId)) return fail(400, "Unknown policy.");
  const parsed = realtimeCostAnomalySchema.safeParse(settings);
  if (!parsed.success) {
    return invalid(parsed.error, "The cost anomaly settings are not valid.");
  }

  return writePolicy({
    providerId,
    policyId,
    attributes: parsed.data,
    unreadable: "The settings were saved but the answer was unreadable.",
  });
};

/**
 * Save only the alert settings. Same shape as the cost settings: updates send
 * just `notifications`, so a stale page cannot overwrite the rest of the
 * policy; a provider without a policy gets one with the API's defaults.
 */
export const saveRealtimeNotifications = async ({
  providerId,
  policyId,
  notifications,
}: {
  providerId: string;
  policyId?: string;
  notifications: RealtimeNotifications;
}): Promise<RealtimeResult<RealtimePolicy>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  if (policyId && !isUuid(policyId)) return fail(400, "Unknown policy.");
  const parsed = realtimeNotificationsSchema.safeParse(notifications);
  if (!parsed.success) {
    const failure = invalid(parsed.error, "The alert settings are not valid.");
    // Same key as the API uses: the whole `notifications` attribute.
    return {
      ...failure,
      fieldErrors: { notifications: failure.error, ...failure.fieldErrors },
    };
  }
  return writePolicy({
    providerId,
    policyId,
    attributes: { notifications: parsed.data },
    unreadable: "The alert settings were saved but the answer was unreadable.",
  });
};

/**
 * Change part of an existing policy (a wizard step, for example). Fields left
 * out keep their stored value, so a step cannot overwrite another one.
 */
export const patchRealtimePolicy = async ({
  providerId,
  policyId,
  patch,
}: {
  providerId: string;
  policyId: string;
  patch: Partial<RealtimePolicyInput>;
}): Promise<RealtimeResult<RealtimePolicy>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  if (!isUuid(policyId)) return fail(400, "Unknown policy.");
  const parsed = realtimePolicyPatchSchema.safeParse(patch);
  if (!parsed.success) {
    return invalid(parsed.error, "The policy is not valid.");
  }
  return writePolicy({
    providerId,
    policyId,
    attributes: parsed.data,
    unreadable: "The policy was saved but the answer was unreadable.",
  });
};

/** The compliance frameworks a policy can enforce. Not paginated. */
export const getRealtimeFrameworks = async (): Promise<
  RealtimeResult<RealtimeFramework[]>
> => {
  const result = await call("frameworks");
  return result.ok
    ? { ok: true, data: resourcesOf(result.document).map(toFramework) }
    : result;
};

// -------------------------------------------------------------------- feed

export const getRealtimeFeed = async (
  providerId: string,
): Promise<RealtimeResult<RealtimeFeed | null>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call("feeds", { query: withProvider(providerId) });
  if (!result.ok) return result;
  const [first] = resourcesOf(result.document);
  return { ok: true, data: first ? toFeed(first) : null };
};

/** An empty queue URL is valid: it selects the CloudTrail LookupEvents fallback. */
export const saveRealtimeFeed = async ({
  providerId,
  feedId,
  feed,
}: {
  providerId: string;
  feedId?: string;
  feed: RealtimeFeedInput;
}): Promise<RealtimeResult<RealtimeFeed>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  if (feedId && !isUuid(feedId)) return fail(400, "Unknown feed.");
  const parsed = realtimeFeedSchema.safeParse(feed);
  if (!parsed.success) {
    return invalid(parsed.error, "The feed is not valid.");
  }

  const result = feedId
    ? await call(`feeds/${feedId}`, {
        method: "PATCH",
        body: toRequestBody({
          type: "realtime-feeds",
          id: feedId,
          attributes: parsed.data,
        }),
      })
    : await call("feeds", {
        method: "POST",
        body: toRequestBody({
          type: "realtime-feeds",
          attributes: parsed.data,
          providerId,
        }),
      });
  if (!result.ok) return result;
  const [saved] = resourcesOf(result.document);
  return saved
    ? { ok: true, data: toFeed(saved) }
    : fail(0, "The feed was saved but the answer was unreadable.");
};

/** Ask for a check now instead of waiting for the next minute (202). */
export const pollRealtimeFeed = async (
  feedId: string,
): Promise<RealtimeResult<{ queued: true }>> => {
  if (!isUuid(feedId)) return fail(400, "Unknown feed.");
  const result = await call(`feeds/${feedId}/poll`, { method: "POST" });
  return result.ok ? { ok: true, data: { queued: true } } : result;
};

export const getRealtimeHealth = async (): Promise<
  RealtimeResult<RealtimeHealth>
> => {
  const result = await call("feeds/health");
  if (!result.ok) return result;
  const [resource] = resourcesOf(result.document);
  return resource
    ? { ok: true, data: toHealth(resource) }
    : fail(0, "The data store status was unreadable.");
};

// ------------------------------------------------------------------ events

export const getRealtimeEvents = async ({
  providerId,
  limit = 100,
  writesOnly = false,
}: {
  providerId: string;
  limit?: number;
  writesOnly?: boolean;
}): Promise<RealtimeResult<RealtimeEvent[]>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const query = new URLSearchParams({
    provider: providerId,
    limit: String(Math.min(Math.max(Math.trunc(limit) || 100, 1), MAX_EVENTS)),
  });
  if (writesOnly) query.set("writes_only", "true");
  const result = await call("events", { query });
  return result.ok
    ? { ok: true, data: resourcesOf(result.document).map(toEvent) }
    : result;
};

// ------------------------------------------------- detections and actions

interface PageOptions {
  providerId: string;
  page?: number;
  pageSize?: number;
}

const pageQuery = (
  providerId: string,
  { page = 1, pageSize = DEFAULT_PAGE_SIZE }: Omit<PageOptions, "providerId">,
  extra: Record<string, string> = {},
) =>
  withProvider(providerId, {
    "page[number]": String(Math.max(Math.trunc(page) || 1, 1)),
    "page[size]": String(
      Math.min(Math.max(Math.trunc(pageSize) || 25, 1), 100),
    ),
    ...extra,
  });

export const getRealtimeDetections = async ({
  providerId,
  statusIn,
  ...paging
}: PageOptions & { statusIn?: string[] }): Promise<
  RealtimeResult<RealtimePage<RealtimeDetection>>
> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call("detections", {
    query: pageQuery(providerId, paging, {
      sort: "-event_time",
      ...(statusIn?.length ? { "filter[status__in]": statusIn.join(",") } : {}),
    }),
  });
  return result.ok
    ? { ok: true, data: toPage(result.document, toDetection) }
    : result;
};

export const getRealtimeActions = async ({
  providerId,
  ...paging
}: PageOptions): Promise<RealtimeResult<RealtimePage<RealtimeAction>>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call("actions", {
    query: pageQuery(providerId, paging, { sort: "-inserted_at" }),
  });
  return result.ok
    ? { ok: true, data: toPage(result.document, toAction) }
    : result;
};

/** Undo an automatic fix with the exact inverse call that was recorded. */
export const revertRealtimeAction = async (
  actionId: string,
): Promise<RealtimeResult<RealtimeAction>> => {
  if (!isUuid(actionId)) return fail(400, "Unknown action.");
  const result = await call(`actions/${actionId}/revert`, { method: "POST" });
  if (!result.ok) return result;
  const [reverted] = resourcesOf(result.document);
  return reverted
    ? { ok: true, data: toAction(reverted) }
    : fail(0, "The change was reverted but the answer was unreadable.");
};

// ------------------------------------------------------------- credentials

export const getRealtimeCredential = async (
  providerId: string,
): Promise<RealtimeResult<RealtimeCredential | null>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call("credentials", { query: withProvider(providerId) });
  if (!result.ok) return result;
  const [first] = resourcesOf(result.document);
  return { ok: true, data: first ? toCredential(first) : null };
};

/** Secrets are write-only: the answer says whether they exist, never what they are. */
export const saveRealtimeCredential = async ({
  providerId,
  credential,
}: {
  providerId: string;
  credential: RealtimeCredentialInput;
}): Promise<RealtimeResult<RealtimeCredential>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const parsed = realtimeCredentialSchema.safeParse(credential);
  if (!parsed.success) {
    return invalid(parsed.error, "The credentials are not valid.");
  }
  // Empty fields are left out so they keep their stored value.
  const attributes = Object.fromEntries(
    Object.entries(parsed.data).filter(([, value]) => Boolean(value)),
  );
  const result = await call("credentials", {
    method: "POST",
    body: toRequestBody({
      type: "realtime-credentials",
      attributes,
      providerId,
    }),
  });
  if (!result.ok) return result;
  const [saved] = resourcesOf(result.document);
  return saved
    ? { ok: true, data: toCredential(saved) }
    : fail(0, "The credentials were saved but the answer was unreadable.");
};

export const deleteRealtimeCredential = async (
  credentialId: string,
): Promise<RealtimeResult<{ deleted: true }>> => {
  if (!isUuid(credentialId)) return fail(400, "Unknown credential.");
  const result = await call(`credentials/${credentialId}`, {
    method: "DELETE",
  });
  return result.ok ? { ok: true, data: { deleted: true } } : result;
};

// ---------------------------------------------------------------- insights

const INSIGHT_KINDS: readonly string[] = Object.values(REALTIME_INSIGHT_KIND);

/** One computed view of an AWS provider. `cost` answers 503 without a data store. */
export const getRealtimeInsight = async <K extends RealtimeInsightKind>(
  kind: K,
  providerId: string,
): Promise<RealtimeResult<RealtimeInsightPayloads[K]>> => {
  if (!INSIGHT_KINDS.includes(kind)) return fail(404, "Unknown view.");
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call(`insights/${kind}`, {
    query: new URLSearchParams({ provider: providerId }),
  });
  if (!result.ok) return result;
  const payload = toInsightPayload(result.document, kind);
  return payload
    ? { ok: true, data: payload }
    : fail(0, "The answer was not in the expected shape.");
};

/**
 * Everything behind one cost anomaly. 404 means the spike is over (or the
 * signal was turned off); 503 means the data store is not available.
 */
export const getRealtimeCostAnomaly = async ({
  providerId,
  service,
  region,
}: {
  providerId: string;
  service: string;
  region: string;
}): Promise<RealtimeResult<RealtimeAnomalyPayload>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  if (!service || !region) return fail(404, "Unknown anomaly.");
  const result = await call("insights/anomaly", {
    query: new URLSearchParams({ provider: providerId, service, region }),
  });
  if (!result.ok) return result;
  const payload = toInsightPayload(
    result.document,
    REALTIME_INSIGHT_KIND.ANOMALY,
  );
  return payload
    ? { ok: true, data: payload }
    : fail(0, "The answer was not in the expected shape.");
};

// ------------------------------------------------- setup, alerts, remediations

/** Where a provider stands in the setup wizard. */
export const getRealtimeSetup = async (
  providerId: string,
): Promise<RealtimeResult<RealtimeSetupPayload>> => {
  if (!isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call("insights/setup", {
    query: new URLSearchParams({ provider: providerId }),
  });
  if (!result.ok) return result;
  const setup = toSetup(result.document);
  return setup
    ? { ok: true, data: setup }
    : fail(0, "The answer was not in the expected shape.");
};

/** The Slack channels and email recipients alerts can go to. */
export const getRealtimeNotificationTargets = async (): Promise<
  RealtimeResult<RealtimeNotificationTargets>
> => {
  const result = await call("notification-targets");
  return result.ok
    ? { ok: true, data: toNotificationTargets(result.document) }
    : result;
};

/**
 * The fixes the remediation role makes possible. With a provider, each says
 * whether it is inside the frameworks that account enforces; without one (demo,
 * no account yet) the list is the same, with no scope.
 */
export const getRealtimeRemediations = async (
  providerId?: string,
): Promise<RealtimeResult<RealtimeRemediation[]>> => {
  if (providerId && !isUuid(providerId)) return fail(400, INVALID_PROVIDER);
  const result = await call("remediations", {
    query: providerId
      ? new URLSearchParams({ provider: providerId })
      : undefined,
  });
  return result.ok
    ? { ok: true, data: resourcesOf(result.document).map(toRemediation) }
    : result;
};

// -------------------------------------------------------------------- demo

const DEMO_KINDS: readonly string[] = [
  ...Object.values(REALTIME_INSIGHT_KIND),
  ...Object.values(REALTIME_DEMO_LIST_KIND),
];

/**
 * Made-up data for an account that is not set up yet: same shapes as the real
 * views, no provider needed. The lists come back as one page.
 */
export const getRealtimeDemo = async <K extends RealtimeDemoKind>(
  kind: K,
): Promise<RealtimeResult<RealtimeDemoPayloads[K]>> => {
  if (!DEMO_KINDS.includes(kind)) return fail(404, "Unknown view.");
  const result = await call(`demo/${kind}`);
  if (!result.ok) return result;
  const payload = toDemoPayload(result.document, kind);
  return payload
    ? { ok: true, data: payload }
    : fail(0, "The answer was not in the expected shape.");
};
