import { afterEach, describe, expect, it, vi } from "vitest";

import { downloadScanZip } from "./helper";

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
});
