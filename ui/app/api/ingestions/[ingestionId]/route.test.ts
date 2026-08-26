import { http, HttpResponse } from "msw";
import { setupServer } from "msw/node";
import {
  afterAll,
  afterEach,
  beforeAll,
  describe,
  expect,
  it,
  vi,
} from "vitest";

import { GET } from "./route";

const { getAuthHeadersMock, isCloudMock } = vi.hoisted(() => ({
  getAuthHeadersMock: vi.fn(),
  isCloudMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/shared/env", () => ({
  isCloud: isCloudMock,
}));

describe("GET /api/ingestions/[ingestionId]", () => {
  const server = setupServer();

  beforeAll(() => server.listen({ onUnhandledRequest: "error" }));

  afterEach(() => {
    server.resetHandlers();
    vi.unstubAllGlobals();
    vi.clearAllMocks();
  });

  afterAll(() => server.close());

  it("returns not found outside Cloud before reading the ingestion identifier", async () => {
    isCloudMock.mockReturnValue(false);
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    const response = await GET(new Request("http://localhost/api/ingestions"), {
      params: Promise.resolve({ ingestionId: "ingestion-123" }),
    });

    expect(response.status).toBe(404);
    expect(getAuthHeadersMock).not.toHaveBeenCalled();
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("forwards a Cloud status request and translates its typed response", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.get("https://api.example.com/api/v1/ingestions/ingestion-123", () =>
        HttpResponse.json({
          data: {
            id: "ingestion-123",
            type: "ingestions",
            attributes: {
              status: "processing",
              summary: { total: 5, processed: 3, invalid: 1 },
              requested_at: "2026-08-26T11:23:20.265770Z",
              started_at: "2026-08-26T11:23:20.372762Z",
              completed_at: null,
            },
          },
        }),
      ),
    );

    const response = await GET(new Request("http://localhost/api/ingestions"), {
      params: Promise.resolve({ ingestionId: "ingestion-123" }),
    });

    await expect(response.json()).resolves.toEqual({
      data: {
        id: "ingestion-123",
        status: "processing",
        totalRecords: 5,
        processedRecords: 3,
        invalidRecords: 1,
      },
    });
  });

  it("sanitizes unreadable upstream status failures", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.get(
        "https://api.example.com/api/v1/ingestions/ingestion-123",
        () =>
          new HttpResponse("<html><body>upstream details</body></html>", {
            status: 503,
            headers: { "content-type": "text/html" },
          }),
      ),
    );

    const response = await GET(new Request("http://localhost/api/ingestions"), {
      params: Promise.resolve({ ingestionId: "ingestion-123" }),
    });

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to retrieve the import status. Please try again.",
    });
  });

  it("does not expose structured upstream status failures", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.get("https://api.example.com/api/v1/ingestions/ingestion-123", () =>
        HttpResponse.json(
          { errors: [{ code: "internal_error", detail: "upstream details" }] },
          { status: 503 },
        ),
      ),
    );

    const response = await GET(new Request("http://localhost/api/ingestions"), {
      params: Promise.resolve({ ingestionId: "ingestion-123" }),
    });

    expect(response.status).toBe(503);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to retrieve the import status. Please try again.",
    });
  });

  it("tracks a status response that has not reported its summary yet", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.get("https://api.example.com/api/v1/ingestions/ingestion-123", () =>
        HttpResponse.json({
          data: {
            type: "ingestions",
            id: "ingestion-123",
            attributes: { status: "pending" },
          },
        }),
      ),
    );

    const response = await GET(new Request("http://localhost/api/ingestions"), {
      params: Promise.resolve({ ingestionId: "ingestion-123" }),
    });

    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({
      data: {
        id: "ingestion-123",
        status: "pending",
        totalRecords: 0,
        processedRecords: 0,
        invalidRecords: 0,
      },
    });
  });

  it("rejects malformed accepted status responses", async () => {
    isCloudMock.mockReturnValue(true);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    server.use(
      http.get("https://api.example.com/api/v1/ingestions/ingestion-123", () =>
        HttpResponse.json({ data: { id: "ingestion-123", attributes: {} } }),
      ),
    );

    const response = await GET(new Request("http://localhost/api/ingestions"), {
      params: Promise.resolve({ ingestionId: "ingestion-123" }),
    });

    expect(response.status).toBe(502);
    await expect(response.json()).resolves.toEqual({
      error: "Unable to retrieve the import status. Please try again.",
    });
  });
});
