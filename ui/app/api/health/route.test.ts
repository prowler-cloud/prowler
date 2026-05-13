import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

interface HealthResponse {
  status: "healthy" | "unhealthy";
  service: "prowler-ui";
  dependencies: {
    api: "healthy" | "unhealthy";
  };
}

const API_HEALTH_URL = "https://api.example.com/health/ready";

const parseHealthResponse = async (response: Response) =>
  (await response.json()) as HealthResponse;

const mockApiHealthResponse = (response: Response) => {
  const fetchMock = vi.fn().mockResolvedValue(response);
  vi.stubGlobal("fetch", fetchMock);

  return fetchMock;
};

describe("GET /api/health", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("should return healthy when the API health endpoint responds successfully", async () => {
    // Given
    vi.stubEnv("PROWLER_API_HEALTH_URL", API_HEALTH_URL);
    const fetchMock = mockApiHealthResponse(
      new Response(null, { status: 200 }),
    );

    // When
    const response = await GET();
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(200);
    expect(body).toEqual({
      status: "healthy",
      service: "prowler-ui",
      dependencies: {
        api: "healthy",
      },
    });
    expect(fetchMock).toHaveBeenCalledWith(
      API_HEALTH_URL,
      expect.objectContaining({
        cache: "no-store",
        signal: expect.any(AbortSignal),
      }),
    );
  });

  it("should return unhealthy when the API health endpoint returns an error status", async () => {
    // Given
    vi.stubEnv("PROWLER_API_HEALTH_URL", API_HEALTH_URL);
    mockApiHealthResponse(new Response(null, { status: 503 }));

    // When
    const response = await GET();
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(503);
    expect(body).toEqual({
      status: "unhealthy",
      service: "prowler-ui",
      dependencies: {
        api: "unhealthy",
      },
    });
  });

  it("should return unhealthy without exposing internal fetch errors", async () => {
    // Given
    vi.stubEnv("PROWLER_API_HEALTH_URL", API_HEALTH_URL);
    vi.stubGlobal(
      "fetch",
      vi.fn().mockRejectedValue(new Error("secret internal hostname failed")),
    );

    // When
    const response = await GET();
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(503);
    expect(body).toEqual({
      status: "unhealthy",
      service: "prowler-ui",
      dependencies: {
        api: "unhealthy",
      },
    });
    expect(JSON.stringify(body)).not.toContain("secret internal hostname");
  });

  it("should return unhealthy when the API health request times out", async () => {
    // Given
    vi.useFakeTimers();
    vi.stubEnv("PROWLER_API_HEALTH_URL", API_HEALTH_URL);
    vi.stubGlobal(
      "fetch",
      vi.fn((_input: RequestInfo | URL, init?: RequestInit) => {
        return new Promise((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            reject(
              new DOMException("The operation was aborted.", "AbortError"),
            );
          });
        });
      }),
    );

    // When
    const responsePromise = GET();
    await vi.runAllTimersAsync();
    const response = await responsePromise;
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(503);
    expect(body).toEqual({
      status: "unhealthy",
      service: "prowler-ui",
      dependencies: {
        api: "unhealthy",
      },
    });
  });

  it("should use the local API health endpoint when the env var is not configured", async () => {
    // Given
    const fetchMock = mockApiHealthResponse(
      new Response(null, { status: 200 }),
    );

    // When
    await GET();

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8080/health/ready",
      expect.any(Object),
    );
  });

  it("should use the local API health endpoint when the env var is blank", async () => {
    // Given
    vi.stubEnv("PROWLER_API_HEALTH_URL", "  ");
    const fetchMock = mockApiHealthResponse(
      new Response(null, { status: 200 }),
    );

    // When
    await GET();

    // Then
    expect(fetchMock).toHaveBeenCalledWith(
      "http://localhost:8080/health/ready",
      expect.any(Object),
    );
  });
});
