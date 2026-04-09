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
  // Simulate real appendSanitizedProviderFilters: appends all non-undefined filters to the URL.
  appendSanitizedProviderFilters: vi.fn(
    (url: URL, filters: Record<string, string | string[] | undefined>) => {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) {
          url.searchParams.append(key, String(value));
        }
      });
    },
  ),
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

// ---------------------------------------------------------------------------
// Resources list keeps FAIL-first sort but no longer forces FAIL-only filtering
// ---------------------------------------------------------------------------

describe("getFindingGroupResources — Blocker 1: FAIL-first sort", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should include the composite sort so FAIL resources appear first, then severity", async () => {
    // Given
    const checkId = "s3_bucket_public_access";

    // When
    await getFindingGroupResources({ checkId });

    // Then — the URL must contain the composite sort
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("sort")).toBe("-severity,-delta,-last_seen_at");
  });

  it("should not force filter[status]=FAIL so PASS resources can also be shown", async () => {
    // Given
    const checkId = "s3_bucket_public_access";

    // When
    await getFindingGroupResources({ checkId });

    // Then — the URL should not add a hardcoded status filter
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("filter[status]")).toBeNull();
  });
});

describe("getLatestFindingGroupResources — Blocker 1: FAIL-first sort", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should include the composite sort so FAIL resources appear first, then severity", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";

    // When
    await getLatestFindingGroupResources({ checkId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("sort")).toBe("-severity,-delta,-last_seen_at");
  });

  it("should not force filter[status]=FAIL so PASS resources can also be shown", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";

    // When
    await getLatestFindingGroupResources({ checkId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("filter[status]")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Triangulation: sort + filter coexist with pagination and caller filters
// ---------------------------------------------------------------------------

describe("getFindingGroupResources — triangulation: params coexist", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should send the composite sort alongside pagination params without forcing filter[status]", async () => {
    // Given
    const checkId = "s3_bucket_versioning";

    // When
    await getFindingGroupResources({ checkId, page: 2, pageSize: 50 });

    // Then — all four params present together
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("page[number]")).toBe("2");
    expect(url.searchParams.get("page[size]")).toBe("50");
    expect(url.searchParams.get("sort")).toBe("-severity,-delta,-last_seen_at");
    expect(url.searchParams.get("filter[status]")).toBeNull();
  });
});

describe("getLatestFindingGroupResources — triangulation: params coexist", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should send the composite sort alongside pagination params without forcing filter[status]", async () => {
    // Given
    const checkId = "iam_root_mfa_enabled";

    // When
    await getLatestFindingGroupResources({ checkId, page: 3, pageSize: 20 });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("page[number]")).toBe("3");
    expect(url.searchParams.get("page[size]")).toBe("20");
    expect(url.searchParams.get("sort")).toBe("-severity,-delta,-last_seen_at");
    expect(url.searchParams.get("filter[status]")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// Caller filters should propagate unchanged to the drill-down resources endpoint
// ---------------------------------------------------------------------------

describe("getFindingGroupResources — caller filters are preserved", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should preserve caller filter[status] when explicitly provided", async () => {
    // Given
    const checkId = "s3_bucket_public_access";
    const filters = { "filter[status]": "PASS" };

    // When
    await getFindingGroupResources({ checkId, filters });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    const allStatusValues = url.searchParams.getAll("filter[status]");
    expect(allStatusValues).toHaveLength(1);
    expect(allStatusValues[0]).toBe("PASS");
  });

  it("should translate a single group status__in filter into filter[status] for resources", async () => {
    // Given
    const checkId = "s3_bucket_public_access";
    const filters = {
      "filter[status__in]": "PASS",
      "filter[severity__in]": "medium",
      "filter[provider_type__in]": "aws",
    };

    // When
    await getFindingGroupResources({ checkId, filters });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("filter[status]")).toBe("PASS");
    expect(url.searchParams.get("filter[status__in]")).toBeNull();
    expect(url.searchParams.get("filter[severity__in]")).toBe("medium");
    expect(url.searchParams.get("filter[provider_type__in]")).toBe("aws");
  });

  it("should keep the composite sort when the resource search filter is applied", async () => {
    // Given
    const checkId = "s3_bucket_public_access";
    const filters = {
      "filter[name__icontains]": "bucket-prod",
      "filter[severity__in]": "high",
    };

    // When
    await getFindingGroupResources({ checkId, filters });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("sort")).toBe("-severity,-delta,-last_seen_at");
    expect(url.searchParams.get("filter[name__icontains]")).toBe("bucket-prod");
    expect(url.searchParams.get("filter[severity__in]")).toBe("high");
  });
});

describe("getLatestFindingGroupResources — caller filters are preserved", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should preserve caller filter[status] when explicitly provided", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";
    const filters = { "filter[status]": "PASS" };

    // When
    await getLatestFindingGroupResources({ checkId, filters });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    const allStatusValues = url.searchParams.getAll("filter[status]");
    expect(allStatusValues).toHaveLength(1);
    expect(allStatusValues[0]).toBe("PASS");
  });

  it("should translate a single group status__in filter into filter[status] for latest resources", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";
    const filters = {
      "filter[status__in]": "PASS",
      "filter[severity__in]": "low",
      "filter[provider_type__in]": "aws",
    };

    // When
    await getLatestFindingGroupResources({ checkId, filters });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("filter[status]")).toBe("PASS");
    expect(url.searchParams.get("filter[status__in]")).toBeNull();
    expect(url.searchParams.get("filter[severity__in]")).toBe("low");
    expect(url.searchParams.get("filter[provider_type__in]")).toBe("aws");
  });

  it("should keep the composite sort when the resource search filter is applied", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";
    const filters = {
      "filter[name__icontains]": "instance-prod",
      "filter[status__in]": "PASS,FAIL",
    };

    // When
    await getLatestFindingGroupResources({ checkId, filters });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("sort")).toBe("-severity,-delta,-last_seen_at");
    expect(url.searchParams.get("filter[name__icontains]")).toBe(
      "instance-prod",
    );
    expect(url.searchParams.get("filter[status__in]")).toBe("PASS,FAIL");
  });
});
