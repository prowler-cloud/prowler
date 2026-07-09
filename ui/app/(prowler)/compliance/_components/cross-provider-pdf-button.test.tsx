import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

import { CrossProviderPdfButton } from "./cross-provider-pdf-button";

// Radix dialogs/dropdowns rely on pointer-capture and scrollIntoView, which
// jsdom does not implement.
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "hasPointerCapture", {
    configurable: true,
    value: vi.fn(() => false),
  });
  Object.defineProperty(HTMLElement.prototype, "setPointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "releasePointerCapture", {
    configurable: true,
    value: vi.fn(),
  });
  Object.defineProperty(HTMLElement.prototype, "scrollIntoView", {
    configurable: true,
    value: vi.fn(),
  });
});

const {
  generatePdfMock,
  trackAndPollMock,
  downloadPdfMock,
  toastMock,
  storeState,
} = vi.hoisted(() => ({
  generatePdfMock: vi.fn(),
  trackAndPollMock: vi.fn(),
  downloadPdfMock: vi.fn(),
  toastMock: vi.fn(),
  storeState: {
    tasks: {} as Record<
      string,
      { kind: string; status: string; meta: Record<string, string> }
    >,
  },
}));

vi.mock("../_actions/cross-provider", () => ({
  generateCrossProviderPdf: generatePdfMock,
}));

vi.mock("../_lib/cross-provider-pdf", () => ({
  CROSS_PROVIDER_PDF_TASK_KIND: "cross-provider-pdf",
  downloadCrossProviderPdf: downloadPdfMock,
  crossProviderPdfHandler: { onReady: vi.fn(), onError: vi.fn() },
}));

vi.mock("@/store/task-watcher/store", () => ({
  trackAndPollTask: trackAndPollMock,
  useTaskWatcherStore: (selector: (state: typeof storeState) => unknown) =>
    selector(storeState),
}));

vi.mock("@/components/shadcn/toast", () => ({
  toast: toastMock,
  ToastAction: () => null,
}));

const props = {
  complianceId: "csa_ccm_4.0",
  filters: { scanIds: ["scan-1"], providerTypes: "aws" },
  latestPdf: null,
};

describe("CrossProviderPdfButton", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    storeState.tasks = {};
    generatePdfMock.mockResolvedValue({ taskId: "task-1" });
  });

  const openGenerateModal = async (
    user: ReturnType<typeof userEvent.setup>,
  ) => {
    await user.click(screen.getByRole("button", { name: /report/i }));
    await user.click(
      await screen.findByRole("menuitem", { name: /generate new report/i }),
    );
  };

  it("generates a report with the dialog options and tracks the task", async () => {
    const user = userEvent.setup();
    render(<CrossProviderPdfButton {...props} />);

    await openGenerateModal(user);
    await user.type(
      screen.getByLabelText(/report name/i),
      "quarterly-audit.pdf",
    );
    await user.click(screen.getByLabelText(/only failed/i));
    await user.click(screen.getByRole("button", { name: /^generate$/i }));

    await waitFor(() => expect(generatePdfMock).toHaveBeenCalledTimes(1));
    expect(generatePdfMock).toHaveBeenCalledWith({
      complianceId: "csa_ccm_4.0",
      filters: props.filters,
      reportName: "quarterly-audit.pdf",
      onlyFailed: true,
      includeManual: false,
    });
    expect(trackAndPollMock).toHaveBeenCalledWith({
      taskId: "task-1",
      kind: "cross-provider-pdf",
      meta: expect.objectContaining({ complianceId: "csa_ccm_4.0" }),
    });
  });

  it("surfaces generation errors as a destructive toast without tracking", async () => {
    generatePdfMock.mockResolvedValue({ error: "No compatible scans." });
    const user = userEvent.setup();
    render(<CrossProviderPdfButton {...props} />);

    await openGenerateModal(user);
    await user.click(screen.getByRole("button", { name: /^generate$/i }));

    await waitFor(() =>
      expect(toastMock).toHaveBeenCalledWith(
        expect.objectContaining({ variant: "destructive" }),
      ),
    );
    expect(trackAndPollMock).not.toHaveBeenCalled();
  });

  it("shows a generating state while a task for this framework is pending", () => {
    storeState.tasks = {
      "task-9": {
        kind: "cross-provider-pdf",
        status: "pending",
        meta: { complianceId: "csa_ccm_4.0" },
      },
    };

    render(<CrossProviderPdfButton {...props} />);

    expect(screen.getByRole("button", { name: /generating/i })).toBeDisabled();
  });

  it("offers an instant download when a matching report already exists", async () => {
    const user = userEvent.setup();
    render(
      <CrossProviderPdfButton
        {...props}
        latestPdf={{
          taskId: "task-7",
          filename: "csa-latest.pdf",
          completedAt: "2026-07-01T10:00:00Z",
        }}
      />,
    );

    await user.click(screen.getByRole("button", { name: /report/i }));
    await user.click(
      await screen.findByRole("menuitem", { name: /download latest/i }),
    );

    await waitFor(() => expect(downloadPdfMock).toHaveBeenCalledWith("task-7"));
  });
});
