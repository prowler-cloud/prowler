import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

const { authMock } = vi.hoisted(() => ({ authMock: vi.fn() }));

vi.mock("@/auth.config", () => ({ auth: authMock }));
vi.mock("@/lib/helper", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
}));

function callRoute(sessionId = "session-1", url = "http://localhost/api") {
  return GET(new Request(url), {
    params: Promise.resolve({ sessionId }),
  });
}

describe("GET /api/lighthouse/v2/sessions/[sessionId]/event-stream", () => {
  beforeEach(() => {
    authMock.mockResolvedValue({ accessToken: "token-123" });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("returns 401 without ever calling upstream when unauthenticated", async () => {
    authMock.mockResolvedValue(null);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await callRoute();

    expect(response.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("proxies the upstream SSE body same-origin with bearer auth", async () => {
    const upstreamBody = new ReadableStream({
      start(controller) {
        controller.enqueue(
          new TextEncoder().encode(
            'event: message.delta\ndata: {"content":"hi"}\n\n',
          ),
        );
        controller.close();
      },
    });
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(upstreamBody, {
        status: 200,
        headers: { "content-type": "text/event-stream" },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);

    const response = await callRoute("session-1");

    // Token is attached server-side (Bearer header), never in the URL.
    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/lighthouse/sessions/session-1/event-stream",
      expect.objectContaining({
        method: "GET",
        cache: "no-store",
        headers: expect.objectContaining({
          Accept: "text/event-stream",
          Authorization: "Bearer token-123",
        }),
        // Client disconnects propagate to the upstream connection.
        signal: expect.any(AbortSignal),
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/event-stream");
    expect(response.headers.get("x-accel-buffering")).toBe("no");
    // Body is piped through, not buffered.
    expect(response.body).toBe(upstreamBody);
  });

  it("forwards the upstream status when the stream cannot be opened", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("not found", { status: 404 })),
    );

    const response = await callRoute("missing");

    expect(response.status).toBe(404);
  });

  it("returns 502 when the upstream API is unreachable", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("ECONNREFUSED")),
    );

    const response = await callRoute();

    expect(response.status).toBe(502);
  });
});
