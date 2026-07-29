"use server";

import { pollTaskUntilSettled } from "@/actions/task/poll";
import type {
  LighthouseV2Configuration,
  LighthouseV2ConfigurationInput,
  LighthouseV2ConfigurationUpdateInput,
  LighthouseV2Message,
  LighthouseV2ProviderType,
  LighthouseV2SendMessageInput,
  LighthouseV2SendMessageResult,
  LighthouseV2Session,
  LighthouseV2SupportedModel,
  LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { apiBaseUrl, getAuthHeaders } from "@/lib/helper";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import type { JsonApiDocument } from "@/types/jsonapi";
import type { ServerActionResult } from "@/types/server-actions";

import {
  buildLighthouseV2ConfigurationPayload,
  buildLighthouseV2ConfigurationUpdatePayload,
  buildLighthouseV2MessagePayload,
  buildLighthouseV2SessionCreatePayload,
  buildLighthouseV2SessionUpdatePayload,
  getJsonApiArray,
  mapLighthouseV2Configuration,
  mapLighthouseV2Message,
  mapLighthouseV2Model,
  mapLighthouseV2Provider,
  mapLighthouseV2Session,
  mapLighthouseV2Task,
  toLighthouseV2ApiProviderType,
  validateLighthouseV2ConfigurationInput,
} from "./lighthouse-v2.adapter";

type TaskResource = Parameters<typeof mapLighthouseV2Task>[0];

export type LighthouseV2ActionResult<T> = ServerActionResult<T>;

const CONFIG_ENDPOINT = "/lighthouse/config";
const SESSIONS_ENDPOINT = "/lighthouse/sessions";
const SUPPORTED_PROVIDERS_ENDPOINT = "/lighthouse/supported-providers";

// 20 attempts x 3s: ~60s ceiling for the provider connection-check task.
const CONNECTION_TEST_MAX_ATTEMPTS = 20;
const CONNECTION_TEST_DELAY_MS = 3000;

export async function getLighthouseV2Configurations(): Promise<
  LighthouseV2ActionResult<LighthouseV2Configuration[]>
> {
  return getCollection(CONFIG_ENDPOINT, mapLighthouseV2Configuration);
}

export async function createLighthouseV2Configuration(
  input: LighthouseV2ConfigurationInput,
): Promise<LighthouseV2ActionResult<LighthouseV2Configuration>> {
  const validation = validateLighthouseV2ConfigurationInput(input);
  if (!validation.success) {
    return { error: validation.error, status: 400 };
  }

  return mutateSingle(
    CONFIG_ENDPOINT,
    {
      method: "POST",
      body: JSON.stringify(buildLighthouseV2ConfigurationPayload(input)),
    },
    mapLighthouseV2Configuration,
    LIGHTHOUSE_ROUTE.SETTINGS,
  );
}

export async function updateLighthouseV2Configuration(
  configId: string,
  input: LighthouseV2ConfigurationUpdateInput,
): Promise<LighthouseV2ActionResult<LighthouseV2Configuration>> {
  return mutateSingle(
    `${CONFIG_ENDPOINT}/${encodeURIComponent(configId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(
        buildLighthouseV2ConfigurationUpdatePayload(configId, input),
      ),
    },
    mapLighthouseV2Configuration,
    LIGHTHOUSE_ROUTE.SETTINGS,
  );
}

export async function deleteLighthouseV2Configuration(
  configId: string,
): Promise<LighthouseV2ActionResult<true>> {
  return mutateEmpty(
    `${CONFIG_ENDPOINT}/${encodeURIComponent(configId)}`,
    { method: "DELETE" },
    LIGHTHOUSE_ROUTE.SETTINGS,
  );
}

// Starts the backend connection-check task, polls it to completion (reusing the
// shared task poller), then returns the re-fetched configuration so the caller
// can render the authoritative `connected` / `connectionLastCheckedAt` status.
export async function testLighthouseV2ConfigurationConnection(
  configId: string,
): Promise<LighthouseV2ActionResult<LighthouseV2Configuration>> {
  try {
    const response = await fetch(
      buildApiUrl(
        `${CONFIG_ENDPOINT}/${encodeURIComponent(configId)}/connection`,
      ),
      { method: "POST", headers: await getAuthHeaders({ contentType: false }) },
    );
    const document = (await handleApiResponse(
      response,
    )) as JsonApiDocument<TaskResource>;
    if (isErrorDocument(document) || !document.data) {
      return toErrorResult(document);
    }

    const settled = await pollTaskUntilSettled(
      mapLighthouseV2Task(document.data).id,
      {
        maxAttempts: CONNECTION_TEST_MAX_ATTEMPTS,
        delayMs: CONNECTION_TEST_DELAY_MS,
      },
    );
    if (!settled.ok) {
      return { error: settled.error || "Connection test timed out." };
    }

    const configurations = await getLighthouseV2Configurations();
    if ("error" in configurations) {
      return configurations;
    }
    const updated = configurations.data.find(
      (config) => config.id === configId,
    );
    if (!updated) {
      return { error: "Configuration not found after connection test." };
    }
    return { data: updated };
  } catch (error) {
    return handleApiError(error);
  }
}

export async function getLighthouseV2SupportedProviders(): Promise<
  LighthouseV2ActionResult<LighthouseV2SupportedProvider[]>
> {
  return getCollection(SUPPORTED_PROVIDERS_ENDPOINT, mapLighthouseV2Provider);
}

export async function getLighthouseV2SupportedModels(
  provider: LighthouseV2ProviderType,
): Promise<LighthouseV2ActionResult<LighthouseV2SupportedModel[]>> {
  return getCollection(
    `${SUPPORTED_PROVIDERS_ENDPOINT}/${encodeURIComponent(toLighthouseV2ApiProviderType(provider))}/models`,
    mapLighthouseV2Model,
  );
}

export async function getLighthouseV2Sessions(): Promise<
  LighthouseV2ActionResult<LighthouseV2Session[]>
> {
  return getCollection(SESSIONS_ENDPOINT, mapLighthouseV2Session);
}

export async function createLighthouseV2Session(
  title?: string | null,
): Promise<LighthouseV2ActionResult<LighthouseV2Session>> {
  // Intentionally NOT revalidating "/lighthouse": the page is force-dynamic
  // (nothing to revalidate) and revalidating the active route mid-submit would
  // re-run the server component and remount the chat, killing the live stream.
  // The sidebar refreshes client-side via notifyLighthouseV2SessionsChanged().
  return mutateSingle(
    SESSIONS_ENDPOINT,
    {
      method: "POST",
      body: JSON.stringify(buildLighthouseV2SessionCreatePayload(title)),
    },
    mapLighthouseV2Session,
    "",
  );
}

export async function updateLighthouseV2Session(
  sessionId: string,
  attributes: { title?: string | null; isArchived?: boolean },
): Promise<LighthouseV2ActionResult<LighthouseV2Session>> {
  return mutateSingle(
    `${SESSIONS_ENDPOINT}/${encodeURIComponent(sessionId)}`,
    {
      method: "PATCH",
      body: JSON.stringify(
        buildLighthouseV2SessionUpdatePayload(sessionId, attributes),
      ),
    },
    mapLighthouseV2Session,
    LIGHTHOUSE_ROUTE.CHAT,
  );
}

export async function archiveLighthouseV2Session(
  sessionId: string,
): Promise<LighthouseV2ActionResult<LighthouseV2Session>> {
  return updateLighthouseV2Session(sessionId, { isArchived: true });
}

export async function getLighthouseV2Messages(
  sessionId: string,
): Promise<LighthouseV2ActionResult<LighthouseV2Message[]>> {
  return getCollection(
    `${SESSIONS_ENDPOINT}/${encodeURIComponent(sessionId)}/messages`,
    mapLighthouseV2Message,
  );
}

export async function sendLighthouseV2Message(
  input: LighthouseV2SendMessageInput,
): Promise<LighthouseV2ActionResult<LighthouseV2SendMessageResult>> {
  try {
    const response = await fetch(
      buildApiUrl(
        `${SESSIONS_ENDPOINT}/${encodeURIComponent(input.sessionId)}/messages`,
      ),
      {
        method: "POST",
        headers: await getAuthHeaders({ contentType: true }),
        body: JSON.stringify(buildLighthouseV2MessagePayload(input)),
      },
    );
    const document = (await handleApiResponse(
      response,
    )) as JsonApiDocument<TaskResource>;

    if (isErrorDocument(document) || !document.data) {
      return toErrorResult(document);
    }

    return {
      data: {
        task: mapLighthouseV2Task(document.data),
      },
      meta: document.meta,
    };
  } catch (error) {
    return handleApiError(error);
  }
}

async function getCollection<TResource, TOutput>(
  path: string,
  mapper: (resource: TResource) => TOutput,
): Promise<LighthouseV2ActionResult<TOutput[]>> {
  return getCollectionFromUrl(buildApiUrl(path), mapper);
}

async function getCollectionFromUrl<TResource, TOutput>(
  url: URL,
  mapper: (resource: TResource) => TOutput,
): Promise<LighthouseV2ActionResult<TOutput[]>> {
  try {
    const headers = await getAuthHeaders({ contentType: false });
    const first = (await handleApiResponse(
      await fetch(url.toString(), {
        method: "GET",
        headers,
        cache: "no-store",
      }),
    )) as JsonApiDocument<TResource[]>;

    if (isErrorDocument(first)) {
      return toErrorResult(first);
    }

    const resources = [...getJsonApiArray(first)];
    let nextUrl: string | undefined = first.links?.next ?? undefined;
    while (nextUrl) {
      const page = (await handleApiResponse(
        await fetch(nextUrl, { method: "GET", headers, cache: "no-store" }),
      )) as JsonApiDocument<TResource[]>;
      if (isErrorDocument(page)) {
        return toErrorResult(page);
      }
      resources.push(...getJsonApiArray(page));
      nextUrl = page.links?.next ?? undefined;
    }

    return {
      data: resources.map(mapper),
      meta: first.meta,
      links: first.links,
    };
  } catch (error) {
    return handleApiError(error);
  }
}

async function mutateSingle<TResource, TOutput>(
  path: string,
  init: RequestInit,
  mapper: (resource: TResource) => TOutput,
  pathToRevalidate: string,
  includeContentType = true,
): Promise<LighthouseV2ActionResult<TOutput>> {
  try {
    const response = await fetch(buildApiUrl(path), {
      ...init,
      headers: await getAuthHeaders({ contentType: includeContentType }),
    });
    const document = (await handleApiResponse(
      response,
      pathToRevalidate,
    )) as JsonApiDocument<TResource>;
    if (isErrorDocument(document) || !document.data) {
      return toErrorResult(document);
    }
    return { data: mapper(document.data), meta: document.meta };
  } catch (error) {
    return handleApiError(error);
  }
}

async function mutateEmpty(
  path: string,
  init: RequestInit,
  pathToRevalidate: string,
): Promise<LighthouseV2ActionResult<true>> {
  try {
    const response = await fetch(buildApiUrl(path), {
      ...init,
      headers: await getAuthHeaders({ contentType: false }),
    });
    const document = await handleApiResponse(response, pathToRevalidate);
    if (isErrorDocument(document)) {
      return toErrorResult(document);
    }
    return { data: true, status: document.status };
  } catch (error) {
    return handleApiError(error);
  }
}

function buildApiUrl(path: string): URL {
  return new URL(`${getRequiredApiBaseUrl()}${path}`);
}

function getRequiredApiBaseUrl(): string {
  if (!apiBaseUrl) {
    throw new Error("API base URL is not configured.");
  }
  return apiBaseUrl;
}

function isErrorDocument<TData>(
  document: JsonApiDocument<TData> | { error?: unknown },
): document is JsonApiDocument<TData> & { error: string } {
  return typeof document.error === "string";
}

function toErrorResult<TData>(
  document: JsonApiDocument<TData>,
): Extract<LighthouseV2ActionResult<never>, { error: string }> {
  return {
    error: document.error ?? "Unexpected Lighthouse AI response.",
    errors: document.errors,
    status: document.status,
  };
}
