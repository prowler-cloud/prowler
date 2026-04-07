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
// Blocker 1 + 2: FAIL-first sort and FAIL-only filter for drill-down resources
// ---------------------------------------------------------------------------

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
// Blocker 1: Resources list must show FAIL first (sort=-status)
// ---------------------------------------------------------------------------

describe("getFindingGroupResources — Blocker 1: FAIL-first sort", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should include sort=-status in the API call so FAIL resources appear first", async () => {
    // Given
    const checkId = "s3_bucket_public_access";

    // When
    await getFindingGroupResources({ checkId });

    // Then — the URL must contain sort=-status
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("sort")).toBe("-status");
  });

  it("should include filter[status]=FAIL in the API call so only impacted resources are shown", async () => {
    // Given
    const checkId = "s3_bucket_public_access";

    // When
    await getFindingGroupResources({ checkId });

    // Then — the URL must contain filter[status]=FAIL
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("filter[status]")).toBe("FAIL");
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

  it("should include sort=-status in the API call so FAIL resources appear first", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";

    // When
    await getLatestFindingGroupResources({ checkId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("sort")).toBe("-status");
  });

  it("should include filter[status]=FAIL in the API call so only impacted resources are shown", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";

    // When
    await getLatestFindingGroupResources({ checkId });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("filter[status]")).toBe("FAIL");
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

  it("should send sort=-status AND filter[status]=FAIL alongside pagination params", async () => {
    // Given
    const checkId = "s3_bucket_versioning";

    // When
    await getFindingGroupResources({ checkId, page: 2, pageSize: 50 });

    // Then — all four params present together
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("page[number]")).toBe("2");
    expect(url.searchParams.get("page[size]")).toBe("50");
    expect(url.searchParams.get("sort")).toBe("-status");
    expect(url.searchParams.get("filter[status]")).toBe("FAIL");
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

  it("should send sort=-status AND filter[status]=FAIL alongside pagination params", async () => {
    // Given
    const checkId = "iam_root_mfa_enabled";

    // When
    await getLatestFindingGroupResources({ checkId, page: 3, pageSize: 20 });

    // Then
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.get("page[number]")).toBe("3");
    expect(url.searchParams.get("page[size]")).toBe("20");
    expect(url.searchParams.get("sort")).toBe("-status");
    expect(url.searchParams.get("filter[status]")).toBe("FAIL");
  });
});

// ---------------------------------------------------------------------------
// Blocker: Duplicate filter[status] — caller-supplied status must be stripped
// ---------------------------------------------------------------------------

describe("getFindingGroupResources — Blocker: caller filter[status] is always overridden to FAIL", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should use filter[status]=FAIL even when caller passes filter[status]=PASS", async () => {
    // Given — caller explicitly passes PASS, which must be ignored
    const checkId = "s3_bucket_public_access";
    const filters = { "filter[status]": "PASS" };

    // When
    await getFindingGroupResources({ checkId, filters });

    // Then — the final URL must have exactly one filter[status]=FAIL, not PASS
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    const allStatusValues = url.searchParams.getAll("filter[status]");
    expect(allStatusValues).toHaveLength(1);
    expect(allStatusValues[0]).toBe("FAIL");
  });

  it("should not have duplicate filter[status] params when caller passes filter[status]", async () => {
    // Given
    const checkId = "s3_bucket_public_access";
    const filters = { "filter[status]": "PASS" };

    // When
    await getFindingGroupResources({ checkId, filters });

    // Then — no duplicates
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.getAll("filter[status]")).toHaveLength(1);
  });
});

describe("getLatestFindingGroupResources — Blocker: caller filter[status] is always overridden to FAIL", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.stubGlobal("fetch", fetchMock);
    getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer token" });
    handleApiResponseMock.mockResolvedValue({ data: [] });
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
  });

  it("should use filter[status]=FAIL even when caller passes filter[status]=PASS", async () => {
    // Given — caller explicitly passes PASS, which must be ignored
    const checkId = "iam_user_mfa_enabled";
    const filters = { "filter[status]": "PASS" };

    // When
    await getLatestFindingGroupResources({ checkId, filters });

    // Then — the final URL must have exactly one filter[status]=FAIL, not PASS
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    const allStatusValues = url.searchParams.getAll("filter[status]");
    expect(allStatusValues).toHaveLength(1);
    expect(allStatusValues[0]).toBe("FAIL");
  });

  it("should not have duplicate filter[status] params when caller passes filter[status]", async () => {
    // Given
    const checkId = "iam_user_mfa_enabled";
    const filters = { "filter[status]": "PASS" };

    // When
    await getLatestFindingGroupResources({ checkId, filters });

    // Then — no duplicates
    const calledUrl = fetchMock.mock.calls[0][0] as string;
    const url = new URL(calledUrl);
    expect(url.searchParams.getAll("filter[status]")).toHaveLength(1);
  });
});
