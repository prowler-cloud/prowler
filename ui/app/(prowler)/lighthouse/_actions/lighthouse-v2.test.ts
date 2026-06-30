import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const { authMock, revalidatePathMock } = vi.hoisted(() => ({
  authMock: vi.fn(),
  revalidatePathMock: vi.fn(),
}));

vi.mock("@/auth.config", () => ({ auth: authMock }));
vi.mock("next/cache", () => ({ revalidatePath: revalidatePathMock }));
vi.mock("@sentry/nextjs", () => ({
  captureException: vi.fn(),
  captureMessage: vi.fn(),
}));
// Provide the primitives the action AND the real handleApiResponse need, while
// keeping the revalidate gate (the behavior under test) running for real.
vi.mock("@/lib/helper", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: vi
    .fn()
    .mockResolvedValue({ Authorization: "Bearer token-123" }),
  parseStringify: (value: unknown) => JSON.parse(JSON.stringify(value)),
  getErrorMessage: (error: unknown) => String(error),
  sanitizeErrorMessage: (message: string) => message,
  GENERIC_SERVER_ERROR_MESSAGE: "Server error",
}));

import {
  createLighthouseV2Session,
  getLighthouseV2SupportedModels,
  updateLighthouseV2Configuration,
  updateLighthouseV2Session,
} from "./lighthouse-v2";

function sessionResponse(id = "session-1") {
  return Response.json(
    {
      data: {
        id,
        type: "lighthouse-sessions",
        attributes: {
          title: "Summarize findings",
          is_archived: false,
          inserted_at: "2026-06-25T10:00:00Z",
          updated_at: "2026-06-25T10:00:00Z",
          active_celery_task_id: null,
        },
      },
    },
    { status: 201 },
  );
}

function configurationResponse(id = "config-1") {
  return Response.json(
    {
      data: {
        id,
        type: "lighthouse-ai-configurations",
        attributes: {
          provider_type: "bedrock",
          base_url: null,
          default_model: "anthropic.claude-4",
          business_context: "Production tenant",
          connected: true,
          connection_last_checked_at: "2026-06-25T10:00:00Z",
          inserted_at: "2026-06-25T09:00:00Z",
          updated_at: "2026-06-25T10:00:00Z",
        },
      },
    },
    { status: 200 },
  );
}

function modelsResponse() {
  return Response.json({ data: [] }, { status: 200 });
}

describe("Lighthouse v2 session write actions", () => {
  beforeEach(() => {
    authMock.mockResolvedValue({ accessToken: "token-123" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("does NOT revalidate /lighthouse when creating a session (avoids chat remount)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(sessionResponse()));

    const result = await createLighthouseV2Session("Summarize findings");

    expect("data" in result && result.data.id).toBe("session-1");
    // Revalidating the active force-dynamic route would remount the chat and
    // kill the live EventSource — so it must stay off for session creation.
    expect(revalidatePathMock).not.toHaveBeenCalled();
  });

  it("still revalidates /lighthouse for other session writes (regression contrast)", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(sessionResponse()));

    await updateLighthouseV2Session("session-1", { title: "Renamed" });

    // Proves the test harness would catch a revalidate being (re)introduced.
    expect(revalidatePathMock).toHaveBeenCalledWith("/lighthouse");
  });

  it("persists the chosen model as the provider default without remounting the active chat", async () => {
    // Given
    const fetchMock = vi.fn().mockResolvedValue(configurationResponse());
    vi.stubGlobal("fetch", fetchMock);

    // When
    const result = await updateLighthouseV2Configuration("config-1", {
      defaultModel: "anthropic.claude-4",
    });

    // Then
    expect("data" in result && result.data.defaultModel).toBe(
      "anthropic.claude-4",
    );
    expect(fetchMock).toHaveBeenCalledWith(
      new URL("https://api.example.com/api/v1/lighthouse/config/config-1"),
      expect.objectContaining({
        method: "PATCH",
        body: JSON.stringify({
          data: {
            type: "lighthouse-ai-configurations",
            id: "config-1",
            attributes: { default_model: "anthropic.claude-4" },
          },
        }),
      }),
    );
    // Revalidating the active force-dynamic chat route would remount it and kill
    // the live EventSource — only the settings route may be revalidated.
    expect(revalidatePathMock).not.toHaveBeenCalledWith("/lighthouse");
    expect(revalidatePathMock).toHaveBeenCalledWith("/lighthouse/settings");
  });

  it("loads OpenAI-compatible models using the Cloud provider id", async () => {
    // Given
    const fetchMock = vi.fn().mockResolvedValue(modelsResponse());
    vi.stubGlobal("fetch", fetchMock);

    // When
    const result = await getLighthouseV2SupportedModels("openai-compatible");

    // Then
    expect("data" in result && result.data).toEqual([]);
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/lighthouse/supported-providers/openai_compatible/models",
      expect.objectContaining({
        method: "GET",
      }),
    );
  });
});
