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
});
