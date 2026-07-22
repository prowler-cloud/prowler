import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const {
  captureExceptionMock,
  fetchMock,
  getAuthHeadersMock,
  handleApiResponseMock,
} = vi.hoisted(() => ({
  captureExceptionMock: vi.fn(),
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  GENERIC_SERVER_ERROR_MESSAGE: "Generic server error.",
  getAuthHeaders: getAuthHeadersMock,
  getErrorMessage: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

vi.mock("@sentry/nextjs", () => ({
  captureException: captureExceptionMock,
}));

import { getCrossAccountComplianceOverview } from "./cross-account";

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

const lastFetchUrl = () => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return new URL(String(call[0]));
};

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValue(jsonResponse({ data: null }));
  getAuthHeadersMock.mockResolvedValue({ Authorization: "Bearer test-token" });
  handleApiResponseMock.mockResolvedValue({ data: null });
});

afterEach(() => {
  vi.useRealTimers();
});

describe("cross-account compliance actions", () => {
  it("loads the overview with its identity and account filters", async () => {
    const payload = { data: { id: "cis_2.0_aws" } };
    handleApiResponseMock.mockResolvedValue(payload);

    const result = await getCrossAccountComplianceOverview({
      complianceId: "cis_2.0_aws",
      providerType: "aws",
      filters: {
        scanIds: ["scan-1", "scan-2"],
        providerIds: "provider-1,provider-2",
        providerGroups: "group-1",
      },
    });

    expect(result).toEqual({ status: "success", response: payload });
    const url = lastFetchUrl();
    expect(url.pathname).toBe("/api/v1/cross-account-compliance-overviews");
    expect(url.searchParams.get("filter[compliance_id]")).toBe("cis_2.0_aws");
    expect(url.searchParams.get("filter[provider_type]")).toBe("aws");
    expect(url.searchParams.get("filter[scan__in]")).toBe("scan-1,scan-2");
    expect(url.searchParams.get("filter[provider_id__in]")).toBe(
      "provider-1,provider-2",
    );
    expect(url.searchParams.get("filter[provider_groups__in]")).toBe("group-1");
  });

  it("aborts a stalled request and reports the network failure", async () => {
    vi.useFakeTimers();
    let requestSignal: AbortSignal | undefined;
    fetchMock.mockImplementation(
      (_input: RequestInfo | URL, init?: RequestInit) =>
        new Promise((_resolve, reject) => {
          requestSignal = init?.signal ?? undefined;
          requestSignal?.addEventListener("abort", () => {
            reject(requestSignal?.reason ?? new Error("aborted"));
          });
        }),
    );

    const request = getCrossAccountComplianceOverview({
      complianceId: "cis_2.0_aws",
      providerType: "aws",
    });
    await vi.advanceTimersByTimeAsync(30_000);

    await expect(request).resolves.toEqual({
      status: "load-error",
      message:
        "Could not load cross-provider compliance data. Try again later.",
    });
    expect(requestSignal?.aborted).toBe(true);
    expect(captureExceptionMock).toHaveBeenCalledTimes(1);
  });
});
