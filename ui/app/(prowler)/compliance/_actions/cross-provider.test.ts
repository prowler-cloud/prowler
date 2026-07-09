import { beforeEach, describe, expect, it, vi } from "vitest";

const {
  fetchMock,
  getAuthHeadersMock,
  handleApiResponseMock,
  captureExceptionMock,
} = vi.hoisted(() => ({
  fetchMock: vi.fn(),
  getAuthHeadersMock: vi.fn(),
  handleApiResponseMock: vi.fn(),
  captureExceptionMock: vi.fn(),
}));

vi.mock("@/lib", () => ({
  apiBaseUrl: "https://api.test/api/v1",
  getAuthHeaders: getAuthHeadersMock,
  getErrorMessage: (error: unknown) =>
    error instanceof Error ? error.message : String(error),
  GENERIC_SERVER_ERROR_MESSAGE: "Generic server error.",
}));

vi.mock("@/lib/server-actions-helper", () => ({
  handleApiResponse: handleApiResponseMock,
}));

vi.mock("@sentry/nextjs", () => ({
  captureException: captureExceptionMock,
}));

import {
  generateCrossProviderPdf,
  getCrossProviderComplianceOverview,
  getCrossProviderPdfBinary,
  getLatestCrossProviderPdf,
} from "./cross-provider";

const lastFetchUrl = (): URL => {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  return new URL(String(call[0]));
};

const jsonResponse = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/vnd.api+json" },
  });

beforeEach(() => {
  vi.clearAllMocks();
  vi.stubGlobal("fetch", fetchMock);
  fetchMock.mockResolvedValue(jsonResponse({ data: null }));
  getAuthHeadersMock.mockResolvedValue({
    Accept: "application/vnd.api+json",
    Authorization: "Bearer test-token",
  });
  handleApiResponseMock.mockResolvedValue({ data: null });
});

describe("getCrossProviderComplianceOverview", () => {
  it("requests the overview with the required compliance_id filter", async () => {
    await getCrossProviderComplianceOverview({ complianceId: "csa_ccm_4.0" });

    const url = lastFetchUrl();
    expect(url.pathname).toBe("/api/v1/cross-provider-compliance-overviews");
    expect(url.searchParams.get("filter[compliance_id]")).toBe("csa_ccm_4.0");
    expect(Array.from(url.searchParams.keys())).toEqual([
      "filter[compliance_id]",
    ]);
  });

  it("serializes optional filters and joins scan ids with commas", async () => {
    await getCrossProviderComplianceOverview({
      complianceId: "dora_2022_2554",
      filters: {
        scanIds: ["scan-1", "scan-2"],
        providerTypes: "aws,gcp",
        providerIds: "prov-1",
        providerGroups: "group-1",
        regions: "eu-west-1",
      },
    });

    const url = lastFetchUrl();
    expect(url.searchParams.get("filter[scan__in]")).toBe("scan-1,scan-2");
    expect(url.searchParams.get("filter[provider_type__in]")).toBe("aws,gcp");
    expect(url.searchParams.get("filter[provider_id__in]")).toBe("prov-1");
    expect(url.searchParams.get("filter[provider_groups__in]")).toBe("group-1");
    expect(url.searchParams.get("filter[region__in]")).toBe("eu-west-1");
  });

  it("returns whatever handleApiResponse resolves for 2xx responses", async () => {
    const payload = { data: { id: "csa_ccm_4.0" } };
    handleApiResponseMock.mockResolvedValue(payload);

    const result = await getCrossProviderComplianceOverview({
      complianceId: "csa_ccm_4.0",
    });

    expect(result).toEqual(payload);
  });

  it("maps 402 to a billing redirect without delegating to handleApiResponse", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ errors: [] }, 402));

    const result = await getCrossProviderComplianceOverview({
      complianceId: "csa_ccm_4.0",
    });

    expect(result).toEqual({ redirectTo: "/billing" });
    expect(handleApiResponseMock).not.toHaveBeenCalled();
  });

  it("returns undefined when the network call throws", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));

    const result = await getCrossProviderComplianceOverview({
      complianceId: "csa_ccm_4.0",
    });

    expect(result).toBeUndefined();
  });
});

describe("generateCrossProviderPdf", () => {
  it("POSTs generate-pdf with filters and report options, returning the task id", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ data: { type: "tasks", id: "task-1" } }, 202),
    );

    const result = await generateCrossProviderPdf({
      complianceId: "csa_ccm_4.0",
      filters: { scanIds: ["scan-1"], providerTypes: "aws" },
      reportName: "quarterly.pdf",
      onlyFailed: true,
      includeManual: false,
    });

    expect(result).toEqual({ taskId: "task-1" });
    const call = fetchMock.mock.calls.at(-1);
    expect((call?.[1] as RequestInit).method).toBe("POST");
    const url = lastFetchUrl();
    expect(url.pathname).toBe(
      "/api/v1/cross-provider-compliance-overviews/generate-pdf",
    );
    expect(url.searchParams.get("filter[compliance_id]")).toBe("csa_ccm_4.0");
    expect(url.searchParams.get("filter[scan__in]")).toBe("scan-1");
    expect(url.searchParams.get("filter[provider_type__in]")).toBe("aws");
    expect(url.searchParams.get("report_name")).toBe("quarterly.pdf");
    expect(url.searchParams.get("only_failed")).toBe("true");
    expect(url.searchParams.get("include_manual")).toBe("false");
  });

  it("omits report options that were not provided", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ data: { type: "tasks", id: "task-1" } }, 202),
    );

    await generateCrossProviderPdf({ complianceId: "csa_ccm_4.0" });

    const url = lastFetchUrl();
    expect(url.searchParams.has("report_name")).toBe(false);
    expect(url.searchParams.has("only_failed")).toBe(false);
    expect(url.searchParams.has("include_manual")).toBe(false);
  });

  it("returns the API error detail when generation fails", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ errors: [{ detail: "No compatible scans." }] }, 422),
    );

    const result = await generateCrossProviderPdf({
      complianceId: "csa_ccm_4.0",
    });

    expect(result).toEqual({ error: "No compatible scans." });
  });

  it("reports 5xx failures to Sentry with the static route template only", async () => {
    fetchMock.mockResolvedValue(jsonResponse({}, 500));

    const result = await generateCrossProviderPdf({
      complianceId: "csa_ccm_4.0",
      reportName: "secret-name.pdf",
    });

    expect(result).toEqual({ error: "Generic server error." });
    expect(captureExceptionMock).toHaveBeenCalledTimes(1);
    const serialized = JSON.stringify(captureExceptionMock.mock.calls[0]);
    expect(serialized).toContain(
      "cross-provider-compliance-overviews/generate-pdf",
    );
    expect(serialized).not.toContain("secret-name");
  });
});

describe("getCrossProviderPdfBinary", () => {
  it("returns pending state on 202", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse(
        { data: { id: "task-1", attributes: { state: "executing" } } },
        202,
      ),
    );

    const result = await getCrossProviderPdfBinary("task-1");

    expect(result).toEqual({
      pending: true,
      state: "executing",
      taskId: "task-1",
    });
    expect(lastFetchUrl().pathname).toBe(
      "/api/v1/cross-provider-compliance-overviews/generate-pdf/task-1/download",
    );
  });

  it("returns the binary as base64 with the content-disposition filename", async () => {
    fetchMock.mockResolvedValue(
      new Response(Buffer.from("pdf-bytes"), {
        status: 200,
        headers: {
          "Content-Type": "application/pdf",
          "Content-Disposition": 'attachment; filename="csa-report.pdf"',
        },
      }),
    );

    const result = await getCrossProviderPdfBinary("task-1");

    expect(result).toEqual({
      success: true,
      data: Buffer.from("pdf-bytes").toString("base64"),
      filename: "csa-report.pdf",
    });
  });

  it("rejects task ids that could smuggle path segments, without fetching", async () => {
    const result = await getCrossProviderPdfBinary("../../../etc/passwd");

    expect(result).toEqual({ error: "Invalid task identifier." });
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns the API error detail on failure", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({ errors: [{ detail: "Report expired." }] }, 410),
    );

    const result = await getCrossProviderPdfBinary("task-1");

    expect(result).toEqual({ error: "Report expired." });
  });
});

describe("getLatestCrossProviderPdf", () => {
  it("returns the report descriptor when a matching report exists", async () => {
    fetchMock.mockResolvedValue(
      jsonResponse({
        data: {
          type: "tasks",
          id: "task-9",
          attributes: {
            completed_at: "2026-07-01T10:00:00Z",
            result: { filename: "csa-latest.pdf" },
          },
        },
      }),
    );

    const result = await getLatestCrossProviderPdf({
      complianceId: "csa_ccm_4.0",
      filters: { scanIds: ["scan-1"] },
    });

    expect(result).toEqual({
      taskId: "task-9",
      filename: "csa-latest.pdf",
      completedAt: "2026-07-01T10:00:00Z",
    });
    const url = lastFetchUrl();
    expect(url.pathname).toBe(
      "/api/v1/cross-provider-compliance-overviews/generate-pdf/latest",
    );
    expect(url.searchParams.get("filter[scan__in]")).toBe("scan-1");
  });

  it("returns null when no report has been generated yet (404)", async () => {
    fetchMock.mockResolvedValue(jsonResponse({ errors: [] }, 404));

    const result = await getLatestCrossProviderPdf({
      complianceId: "csa_ccm_4.0",
    });

    expect(result).toBeNull();
  });

  it("degrades to null on unexpected failures", async () => {
    fetchMock.mockRejectedValue(new Error("boom"));

    const result = await getLatestCrossProviderPdf({
      complianceId: "csa_ccm_4.0",
    });

    expect(result).toBeNull();
  });
});
