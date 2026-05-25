import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

const { getAuthHeadersMock } = vi.hoisted(() => ({
  getAuthHeadersMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

describe("GET /api/scans/[scanId]/report", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  it("streams the upstream report body without buffering it", async () => {
    const upstreamBody = new ReadableStream({
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
        controller.close();
      },
    });
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(upstreamBody, {
        status: 200,
        headers: {
          "content-type": "application/zip",
          "content-length": "3",
        },
      }),
    );
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });

    const response = await GET(new Request("http://localhost/api"), {
      params: Promise.resolve({ scanId: "scan-123" }),
    });

    expect(fetchMock).toHaveBeenCalledWith(
      "https://api.example.com/api/v1/scans/scan-123/report",
      expect.objectContaining({
        headers: { Authorization: "Bearer token" },
        cache: "no-store",
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/zip");
    expect(response.headers.get("content-length")).toBe("3");
    expect(response.headers.get("content-disposition")).toBe(
      'attachment; filename="scan-scan-123-report.zip"',
    );
    expect(response.body).toBe(upstreamBody);
  });

  it("checks report readiness without streaming ready report bytes", async () => {
    const cancelMock = vi.fn();
    const upstreamBody = new ReadableStream({
      cancel: cancelMock,
      start(controller) {
        controller.enqueue(new Uint8Array([1, 2, 3]));
      },
    });
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(upstreamBody, { status: 200 })),
    );
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });

    const response = await GET(
      new Request("http://localhost/api?preflight=1"),
      {
        params: Promise.resolve({ scanId: "scan-123" }),
      },
    );

    expect(response.status).toBe(204);
    expect(response.body).toBeNull();
    expect(cancelMock).toHaveBeenCalledTimes(1);
  });

  it("preserves pending report responses from the API", async () => {
    vi.stubGlobal(
      "fetch",
      vi
        .fn()
        .mockResolvedValue(
          Response.json({ data: { id: "task-1" } }, { status: 202 }),
        ),
    );
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });

    const response = await GET(new Request("http://localhost/api"), {
      params: Promise.resolve({ scanId: "scan-123" }),
    });

    expect(response.status).toBe(202);
    await expect(response.json()).resolves.toEqual({ data: { id: "task-1" } });
  });
});
