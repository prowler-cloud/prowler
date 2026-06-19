import { afterEach, describe, expect, it, vi } from "vitest";

import { GET } from "./route";

interface HealthResponse {
  status: "pass";
  version: string;
  releaseId: string;
  serviceId: "prowler-ui";
  description: string;
}

const parseHealthResponse = async (response: Response) =>
  (await response.json()) as HealthResponse;

describe("GET /api/health", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.unstubAllGlobals();
  });

  it("should return an IETF-shaped healthy response when the Next.js route handler responds", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_PROWLER_RELEASE_VERSION", "1.28.0");

    // When
    const response = await GET();
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(200);
    expect(response.headers.get("Content-Type")).toBe(
      "application/health+json",
    );
    expect(response.headers.get("Cache-Control")).toBe("no-store");
    expect(body).toEqual({
      status: "pass",
      version: "1",
      releaseId: "1.28.0",
      serviceId: "prowler-ui",
      description: "Prowler UI",
    });
  });

  it("should fall back to 'unknown' when the release version env var is missing", async () => {
    // Given
    vi.stubEnv("NEXT_PUBLIC_PROWLER_RELEASE_VERSION", "");

    // When
    const response = await GET();
    const body = await parseHealthResponse(response);

    // Then
    expect(response.status).toBe(200);
    expect(body.releaseId).toBe("unknown");
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

  it("should not depend on external health URLs", async () => {
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
    expect(body.status).toBe("pass");
    expect(body.serviceId).toBe("prowler-ui");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});
