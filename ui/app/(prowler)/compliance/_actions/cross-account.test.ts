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

const lastFetchCall = () => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
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
    const { init, url } = lastFetchCall();
    expect(url.pathname).toBe("/api/v1/cross-account-compliance-overviews");
    expect(url.searchParams.get("filter[compliance_id]")).toBe("cis_2.0_aws");
    expect(url.searchParams.get("filter[provider_type]")).toBe("aws");
    expect(url.searchParams.get("filter[scan__in]")).toBe("scan-1,scan-2");
    expect(url.searchParams.get("filter[provider_id__in]")).toBe(
      "provider-1,provider-2",
    );
    expect(url.searchParams.get("filter[provider_groups__in]")).toBe("group-1");
    expect(init.signal).toBeInstanceOf(AbortSignal);
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

  it("starts PDF generation through the shared task protocol", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ data: { type: "tasks", id: "task-1" } }, 202),
    );

    const result = await generateCrossAccountPdf({
      complianceId: "cis_2.0_aws",
      providerType: "aws",
      filters: { scanIds: ["scan-1"] },
      reportName: "aws-report.pdf",
    });

    expect(result).toEqual({ taskId: "task-1" });
    const { init, url } = lastFetchCall();
    expect(init.method).toBe("POST");
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(url.pathname).toBe("/api/v1/cross-account-compliance-overviews/pdf");
    expect(url.searchParams.get("report_name")).toBe("aws-report.pdf");
  });

  it("retrieves a completed PDF with its response filename", async () => {
    fetchMock.mockResolvedValue(
      new Response(Buffer.from("pdf-bytes"), {
        headers: {
          "Content-Disposition": 'attachment; filename="aws-report.pdf"',
          "Content-Type": "application/pdf",
        },
      }),
    );

    const result = await getCrossAccountPdfBinary("task-1");

    expect(result).toEqual({
      success: true,
      data: Buffer.from("pdf-bytes").toString("base64"),
      filename: "aws-report.pdf",
    });
    expect(lastFetchCall().init.signal).toBeInstanceOf(AbortSignal);
  });

  it("returns the latest matching PDF descriptor", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        data: {
          id: "task-9",
          attributes: {
            completed_at: "2026-07-01T10:00:00Z",
            result: { filename: "latest.pdf" },
          },
        },
      }),
    );

    const result = await getLatestCrossAccountPdf({
      complianceId: "cis_2.0_aws",
      providerType: "aws",
      filters: { providerIds: "provider-1" },
    });

    expect(result).toEqual({
      taskId: "task-9",
      filename: "latest.pdf",
      completedAt: "2026-07-01T10:00:00Z",
    });
    const { init, url } = lastFetchCall();
    expect(init.signal).toBeInstanceOf(AbortSignal);
    expect(url.pathname).toBe(
      "/api/v1/cross-account-compliance-overviews/pdf/latest",
    );
    expect(url.searchParams.get("filter[provider_id__in]")).toBe("provider-1");
  });
});
