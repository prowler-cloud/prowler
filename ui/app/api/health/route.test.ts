import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

interface HealthResponse {
  status: "healthy";
  service: "prowler-ui";
}

const parseHealthResponse = async (response: Response) =>
  (await response.json()) as HealthResponse;

describe("GET /api/health", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("should return a healthy response when the Next.js route handler responds", async () => {
    // Given
    const expectedBody: HealthResponse = {
      status: "healthy",
      service: "prowler-ui",
    };

    // When
    const response = await GET();
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(200);
    expect(body).toEqual(expectedBody);
  });

  it("should not call fetch while evaluating UI liveness", async () => {
    // Given
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    // When
    await GET();

    // Then
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("should ignore PROWLER_API_HEALTH_URL", async () => {
    // Given
    vi.stubEnv(
      "PROWLER_API_HEALTH_URL",
      "https://api.example.com/health/ready",
    );
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);

    // When
    const response = await GET();
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(200);
    expect(body).toEqual({
      status: "healthy",
      service: "prowler-ui",
    });
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
