import { beforeEach, describe, expect, it, vi } from "vitest";

// ---------------------------------------------------------------------------
// Hoisted mocks (must be declared before any imports that need them)
// ---------------------------------------------------------------------------

const { fetchMock, getAuthHeadersMock, handleApiResponseMock } = vi.hoisted(
  () => ({
    fetchMock: vi.fn(),
    getAuthHeadersMock: vi.fn(),
    handleApiResponseMock: vi.fn(),
  }),
);

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.example.com/api/v1",
  getAuthHeaders: getAuthHeadersMock,
}));

vi.mock("@/lib/provider-filters", () => ({
  appendSanitizedProviderFilters: vi.fn(),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

vi.mock("next/navigation", () => ({
  redirect: vi.fn(),
}));

// ---------------------------------------------------------------------------
// Imports (after vi.mock declarations)
// ---------------------------------------------------------------------------

import {
  getFindingGroupResources,
  getLatestFindingGroupResources,
} from "./finding-groups";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe("getFindingGroupResources — SSRF path traversal protection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should encode a normal checkId without alteration", async () => {
    // Given
    const checkId = "s3_bucket_public_access";

    // When
    await getFindingGroupResources({ checkId });

    // Then — URL path must contain encoded checkId, not raw
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain(
      `/api/v1/finding-groups/${encodeURIComponent(checkId)}/resources`,
    );
  });

  it("should encode a checkId containing a forward slash (path traversal attempt)", async () => {
    // Given — checkId with embedded slash: attacker attempts path traversal
    const maliciousCheckId = "../../admin/secret";

    // When
    await getFindingGroupResources({ checkId: maliciousCheckId });

    // Then — the URL must NOT contain a raw slash from the checkId
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    // The path should NOT end in /resources with traversal segments between
    expect(url.pathname).not.toContain("/admin/secret/resources");
    // The encoded checkId must appear in the path
    expect(url.pathname).toContain(
      `/finding-groups/${encodeURIComponent(maliciousCheckId)}/resources`,
    );
  });

  it("should encode a checkId containing %2F (URL-encoded slash traversal attempt)", async () => {
    // Given — checkId with %2F: double-encoding traversal attempt
    const maliciousCheckId = "foo%2Fbar";

    // When
    await getFindingGroupResources({ checkId: maliciousCheckId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.pathname).toContain(
      `/finding-groups/${encodeURIComponent(maliciousCheckId)}/resources`,
    );
    expect(url.pathname).not.toContain("/foo/bar/resources");
  });

  it("should encode a checkId containing special chars like ? and #", async () => {
    // Given
    const maliciousCheckId = "check?admin=true#fragment";

    // When
    await getFindingGroupResources({ checkId: maliciousCheckId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).not.toContain("?admin=true");
    expect(calledUrl.split("?")[0]).toContain(
      `/finding-groups/${encodeURIComponent(maliciousCheckId)}/resources`,
    );
  });
});

describe("getLatestFindingGroupResources — SSRF path traversal protection", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should encode a normal checkId without alteration", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";

    // When
    await getLatestFindingGroupResources({ checkId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    expect(calledUrl).toContain(
      `/api/v1/finding-groups/latest/${encodeURIComponent(checkId)}/resources`,
    );
  });

  it("should encode a checkId containing a forward slash in the latest endpoint", async () => {
    // Given
    const maliciousCheckId = "../other-endpoint";

    // When
    await getLatestFindingGroupResources({ checkId: maliciousCheckId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.pathname).not.toContain("/other-endpoint/resources");
    expect(url.pathname).toContain(
      `/finding-groups/latest/${encodeURIComponent(maliciousCheckId)}/resources`,
    );
  });
});
