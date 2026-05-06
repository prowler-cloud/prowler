"use server";

import * as Sentry from "@sentry/nextjs";

import { apiBaseUrl, getAuthHeaders } from "@/lib";

import { buildAlertsDisabledResult, isAlertsEnabled } from "../_lib/env";
import {
  buildSuccessResult,
  buildUnexpectedError,
  mapJsonApiErrorToAction,
} from "../_lib/error-mapping";
import type { AlertsActionResult } from "../_types";

export interface AlertsRequestOptions {
  method?: "GET" | "POST" | "PATCH" | "DELETE" | "OPTIONS";
  query?: URLSearchParams | Record<string, string | string[] | undefined>;
  body?: unknown;
  contentType?: boolean;
  attachAuth?: boolean;
  cache?: RequestCache;
  signal?: AbortSignal;
}

const isPairArray = (
  value: unknown,
): value is ReadonlyArray<readonly [string, string]> =>
  Array.isArray(value) &&
  value.every(
    (entry) =>
      Array.isArray(entry) && entry.length >= 2 && typeof entry[0] === "string",
  );

const buildUrl = (
  path: string,
  query: AlertsRequestOptions["query"],
): string => {
  if (!apiBaseUrl) {
    throw new Error("NEXT_PUBLIC_API_BASE_URL is not configured.");
  }
  const url = new URL(`${apiBaseUrl}${path}`);
  if (!query) return url.toString();
  // Real URLSearchParams (RSC → action call within the same process).
  if (query instanceof URLSearchParams) {
    query.forEach((value, key) => url.searchParams.append(key, value));
    return url.toString();
  }
  // Serialized URLSearchParams shape (client → server action crosses the
  // boundary; Next.js converts URLSearchParams to its [[k, v], ...] form).
  if (isPairArray(query)) {
    for (const [key, value] of query) {
      url.searchParams.append(key, String(value ?? ""));
    }
    return url.toString();
  }
  for (const [key, value] of Object.entries(query)) {
    if (value === undefined) continue;
    if (Array.isArray(value)) {
      for (const v of value) url.searchParams.append(key, v);
      continue;
    }
    url.searchParams.set(key, value);
  }
  return url.toString();
};

const safeJson = async (response: Response): Promise<unknown> => {
  const text = await response.text().catch(() => "");
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
};

export const alertsRequest = async <T>(
  path: string,
  options: AlertsRequestOptions = {},
): Promise<AlertsActionResult<T>> => {
  if (!isAlertsEnabled()) {
    return buildAlertsDisabledResult<T>();
  }

  const {
    method = "GET",
    query,
    body,
    contentType = method !== "GET" && method !== "DELETE",
    attachAuth = true,
    cache,
    signal,
  } = options;
  try {
    const baseHeaders = attachAuth
      ? await getAuthHeaders({ contentType })
      : ({
          Accept: "application/vnd.api+json",
          ...(contentType
            ? { "Content-Type": "application/vnd.api+json" }
            : {}),
        } as Record<string, string>);
    const headers: Record<string, string> = { ...baseHeaders };

    const url = buildUrl(path, query);
    const response = await fetch(url, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      cache: cache ?? "no-store",
      signal,
    });

    if (!response.ok) {
      const parsedBody = (await safeJson(response)) as Parameters<
        typeof mapJsonApiErrorToAction
      >[1];
      const error = mapJsonApiErrorToAction(
        response.status,
        parsedBody,
        response.headers.get("retry-after"),
      );
      Sentry.addBreadcrumb({
        category: "alerts.request",
        message: `${method} ${path} failed`,
        level: "warning",
        data: {
          status: response.status,
          code: error.code,
          retry_after_seconds: error.retryAfterSeconds,
        },
      });
      return { ok: false, error };
    }

    if (response.status === 204) {
      return buildSuccessResult(undefined as T, null);
    }

    const parsed = (await safeJson(response)) as Parameters<
      typeof mapJsonApiErrorToAction
    >[1] & { data?: unknown };
    return buildSuccessResult((parsed ?? null) as T, parsed);
  } catch (error) {
    Sentry.captureException(error, {
      tags: { error_source: "alerts.request", method },
      level: "error",
    });
    return {
      ok: false,
      error: buildUnexpectedError(
        error instanceof Error ? error.message : "Unexpected error.",
      ),
    };
  }
};
