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

import {
  generateCrossAccountPdf,
  getCrossAccountComplianceOverview,
  getCrossAccountPdfBinary,
  getLatestCrossAccountPdf,
} from "./cross-account";

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

const fetchCallAt = (index: number) => {
  const call = fetchMock.mock.calls[index];
  if (!call) throw new Error(`fetch call ${index} was not found`);
  return {
    init: call[1] as RequestInit,
    url: new URL(String(call[0])),
  };
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

  it("routes PDF operations through the cross-account endpoints", async () => {
    fetchMock
      .mockResolvedValueOnce(
        jsonResponse({ data: { type: "tasks", id: "task-1" } }, 202),
      )
      .mockResolvedValueOnce(
        new Response(Buffer.from("pdf-bytes"), {
          headers: {
            "Content-Disposition": 'attachment; filename="report.pdf"',
            "Content-Type": "application/pdf",
          },
        }),
      )
      .mockResolvedValueOnce(
        jsonResponse({
          data: {
            id: "task-2",
            attributes: { result: { filename: "latest.pdf" } },
          },
        }),
      );

    await generateCrossAccountPdf({
      complianceId: "cis_2.0_aws",
      providerType: "aws",
      filters: { scanIds: ["scan-1"] },
      reportName: "report.pdf",
    });
    await getCrossAccountPdfBinary("task-1");
    await getLatestCrossAccountPdf({
      complianceId: "cis_2.0_aws",
      providerType: "aws",
      filters: { providerIds: "provider-1" },
    });

    const generation = fetchCallAt(0);
    expect(generation.init.method).toBe("POST");
    expect(generation.url.pathname).toBe(
      "/api/v1/cross-account-compliance-overviews/pdf",
    );
    expect(generation.url.searchParams.get("filter[compliance_id]")).toBe(
      "cis_2.0_aws",
    );
    expect(generation.url.searchParams.get("filter[provider_type]")).toBe(
      "aws",
    );
    expect(generation.url.searchParams.get("filter[scan__in]")).toBe("scan-1");
    expect(generation.url.searchParams.get("report_name")).toBe("report.pdf");

    const binary = fetchCallAt(1);
    expect(binary.url.pathname).toBe(
      "/api/v1/cross-account-compliance-overviews/pdf/task-1",
    );

    const latest = fetchCallAt(2);
    expect(latest.url.pathname).toBe(
      "/api/v1/cross-account-compliance-overviews/pdf/latest",
    );
    expect(latest.url.searchParams.get("filter[provider_id__in]")).toBe(
      "provider-1",
    );

    expect([generation, binary, latest].every(({ init }) => init.signal)).toBe(
      true,
    );
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
