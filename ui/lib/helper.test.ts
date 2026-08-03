import { afterEach, describe, expect, it, vi } from "vitest";

import { getTask } from "@/actions/task";

import {
  checkTaskStatus,
  downloadScanZip,
  getErrorMessage,
  permissionFormFields,
} from "./helper";

vi.mock("@/actions/scans", () => ({
  getComplianceCsv: vi.fn(),
  getCompliancePdfReport: vi.fn(),
}));

vi.mock("@/actions/task", () => ({
  getTask: vi.fn(),
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
  const taskWithState = (state: string, result?: unknown) => ({
    data: { id: "task-1", attributes: { state, result } },
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("reports the task's own error when it was cancelled", async () => {
    // Given a revoked task, which the API reports as `cancelled`
    vi.mocked(getTask).mockResolvedValue(
      taskWithState("cancelled", { error: "Worker lost the connection" }),
    );

    // When
    const status = await checkTaskStatus("task-1", 1, 0);

    // Then
    expect(status.completed).toBe(false);
    expect(status.error).toBe("Worker lost the connection");
    expect(status.task).toBeDefined();
  });

  it("names the state when a settled task carries no result", async () => {
    // Given a settled task with no `result`
    vi.mocked(getTask).mockResolvedValue(taskWithState("cancelled"));

    // When
    const status = await checkTaskStatus("task-1", 1, 0);

    // Then
    expect(status).toMatchObject({ completed: false, error: "Task cancelled" });
  });

  it("still reports a failed task's error", async () => {
    // Given
    vi.mocked(getTask).mockResolvedValue(
      taskWithState("failed", { error: "Invalid credentials" }),
    );

    // When
    const status = await checkTaskStatus("task-1", 1, 0);

    // Then
    expect(status).toMatchObject({
      completed: false,
      error: "Invalid credentials",
    });
  });

  it("keeps polling while the task is still executing", async () => {
    // Given a task that settles on the second read
    vi.mocked(getTask)
      .mockResolvedValueOnce(taskWithState("executing"))
      .mockResolvedValueOnce(taskWithState("completed"));

    // When
    const status = await checkTaskStatus("task-1", 3, 0);

    // Then
    expect(status.completed).toBe(true);
    expect(getTask).toHaveBeenCalledTimes(2);
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
