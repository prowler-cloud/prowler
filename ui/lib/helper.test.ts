import { afterEach, describe, expect, it, vi } from "vitest";

import {
  checkTaskStatus,
  downloadScanZip,
  getErrorMessage,
  permissionFormFields,
  TASK_STATUS_MAX_RETRIES_ERROR,
} from "./helper";

vi.mock("@/actions/scans", () => ({
  getComplianceCsv: vi.fn(),
  getCompliancePdfReport: vi.fn(),
}));

const { getTask } = vi.hoisted(() => ({ getTask: vi.fn() }));
vi.mock("@/actions/task", () => ({
  getTask,
}));

vi.mock("@/auth.config", () => ({
  auth: vi.fn(),
}));

const createToast = () => vi.fn();

const getAnchor = () => {
  const anchor = document.createElement("a");
  const clickMock = vi.spyOn(anchor, "click").mockImplementation(() => {});
  vi.spyOn(document, "createElement").mockReturnValue(anchor);
  return { anchor, clickMock };
};

describe("downloadScanZip", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    document.body.replaceChildren();
  });

  it("preflights the report and starts a browser-native download when ready", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(null, { status: 204 })),
    );
    const { anchor, clickMock } = getAnchor();
    const toast = createToast();

    await downloadScanZip("scan-123", toast);

    expect(fetch).toHaveBeenCalledWith(
      "/api/scans/scan-123/report?preflight=1",
      {
        cache: "no-store",
      },
    );
    expect(anchor.href).toContain("/api/scans/scan-123/report");
    expect(anchor.download).toBe("scan-scan-123-report.zip");
    expect(clickMock).toHaveBeenCalledTimes(1);
    expect(toast).toHaveBeenCalledWith({
      title: "Download Started",
      description: "Your browser is downloading the scan report.",
    });
  });

  it("shows the pending report message without starting a download", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("{}", { status: 202 })),
    );
    const { clickMock } = getAnchor();
    const toast = createToast();

    await downloadScanZip("scan-123", toast);

    expect(clickMock).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith({
      title: "The report is still being generated",
      description: "Please try again in a few minutes.",
    });
  });

  it("shows an error without starting a download when preflight fails", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response("not found", { status: 404 })),
    );
    const { clickMock } = getAnchor();
    const toast = createToast();

    await downloadScanZip("scan-123", toast);

    expect(clickMock).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith({
      variant: "destructive",
      title: "Download Failed",
      description: "not found",
    });
  });

  it("shows a generic error when preflight fails with an HTML gateway page", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(
          "<html><body><h1>504 Gateway Time-out</h1></body></html>",
          {
            status: 504,
            headers: { "content-type": "text/html" },
          },
        ),
      ),
    );
    const { clickMock } = getAnchor();
    const toast = createToast();

    await downloadScanZip("scan-123", toast);

    expect(clickMock).not.toHaveBeenCalled();
    expect(toast).toHaveBeenCalledWith({
      variant: "destructive",
      title: "Download Failed",
      description:
        "Unable to prepare the scan report. Please try again in a few minutes.",
    });
  });
});

describe("getErrorMessage", () => {
  it("does not expose HTML gateway pages", () => {
    // Given
    const error = new Error(
      "<html><head><title>502 Bad Gateway</title></head><body><h1>502 Bad Gateway</h1></body></html>",
    );

    // When
    const message = getErrorMessage(error);

    // Then
    expect(message).toBe(
      "Server is temporarily unavailable. Please try again in a few minutes.",
    );
  });
});

describe("checkTaskStatus", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("keeps polling past a caller's default retry window and reports success once the task completes", async () => {
    let calls = 0;
    getTask.mockImplementation(async () => {
      calls += 1;
      if (calls < 25) {
        return { data: { attributes: { state: "executing" } } };
      }
      return { data: { attributes: { state: "completed" } } };
    });

    // 25 retries exceeds the generic 20-retry default, simulating a task that
    // outlives the caller's usual wait.
    const result = await checkTaskStatus("task-id", 40, 1);

    expect(result.completed).toBe(true);
    expect(calls).toBe(25);
  });

  it("reports the exhausted-retries error once maxRetries is used up", async () => {
    getTask.mockResolvedValue({ data: { attributes: { state: "executing" } } });

    const result = await checkTaskStatus("task-id", 3, 1);

    expect(result).toEqual({
      completed: false,
      error: TASK_STATUS_MAX_RETRIES_ERROR,
    });
    expect(getTask).toHaveBeenCalledTimes(3);
  });
});

describe("permissionFormFields", () => {
  it("describes Unlimited Visibility as organization-wide", () => {
    // Given
    const field = permissionFormFields.find(
      ({ field }) => field === "unlimited_visibility",
    );

    // When
    const description = field?.description;

    // Then
    expect(description).toContain("organization-wide visibility");
    expect(description).not.toContain("tenant-wide");
  });
});
