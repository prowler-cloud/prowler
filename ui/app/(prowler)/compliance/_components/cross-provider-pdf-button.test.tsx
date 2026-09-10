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
  generateAccountPdfMock,
  trackAndPollMock,
  downloadPdfMock,
  downloadAccountPdfMock,
  toastMock,
  storeState,
} = vi.hoisted(() => ({
  generatePdfMock: vi.fn(),
  generateAccountPdfMock: vi.fn(),
  trackAndPollMock: vi.fn(),
  downloadPdfMock: vi.fn(),
  downloadAccountPdfMock: vi.fn(),
  toastMock: vi.fn(),
  storeState: {
    tasks: {} as Record<
      string,
      {
        taskId: string;
        kind: string;
        status: string;
        meta: Record<string, string>;
        startedAt: number;
      }
    >,
  },
}));

vi.mock("../_actions/cross-provider", () => ({
  generateCrossProviderPdf: generatePdfMock,
}));

vi.mock("../_actions/cross-account", () => ({
  generateCrossAccountPdf: generateAccountPdfMock,
}));

vi.mock("../_lib/cross-provider-pdf", () => ({
  CROSS_PROVIDER_PDF_TASK_KIND: "cross-provider-pdf",
  buildCrossProviderPdfTaskScope: vi.fn(() => "scope-1"),
  downloadCrossProviderPdf: downloadPdfMock,
  crossProviderPdfHandler: { onReady: vi.fn(), onError: vi.fn() },
}));

vi.mock("../_lib/cross-account-pdf", () => ({
  CROSS_ACCOUNT_PDF_TASK_KIND: "cross-account-pdf",
  buildCrossAccountPdfTaskScope: vi.fn(() => "account-scope-1"),
  downloadCrossAccountPdf: downloadAccountPdfMock,
  crossAccountPdfHandler: { onReady: vi.fn(), onError: vi.fn() },
}));

vi.mock("@/store/task-watcher/store", () => ({
  TASK_WATCHER_STATUS: { PENDING: "pending", READY: "ready", ERROR: "error" },
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

  it("generates a named report without unsupported requirement options", async () => {
    // Given
    const user = userEvent.setup();
    render(<CrossProviderPdfButton {...props} />);

    // When
    await openGenerateModal(user);
    await user.type(
      screen.getByLabelText(/report name/i),
      "quarterly-audit.pdf",
    );
    expect(screen.queryByLabelText(/only failed/i)).not.toBeInTheDocument();
    expect(screen.queryByLabelText(/include manual/i)).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: /^generate$/i }));

    // Then
    await waitFor(() => expect(generatePdfMock).toHaveBeenCalledTimes(1));
    expect(generatePdfMock).toHaveBeenCalledWith({
      complianceId: "csa_ccm_4.0",
      filters: props.filters,
      reportName: "quarterly-audit.pdf",
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
        taskId: "task-9",
        kind: "cross-provider-pdf",
        status: "pending",
        meta: { complianceId: "csa_ccm_4.0", scopeKey: "scope-1" },
        startedAt: Date.now(),
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

  it("keeps a completed report downloadable after the ready toast closes", async () => {
    // Given
    storeState.tasks = {
      "task-8": {
        taskId: "task-8",
        kind: "cross-provider-pdf",
        status: "ready",
        meta: {
          complianceId: "csa_ccm_4.0",
          scopeKey: "scope-1",
          reportLabel: "quarterly-audit.pdf",
        },
        startedAt: Date.now(),
      },
    };
    const user = userEvent.setup();
    render(<CrossProviderPdfButton {...props} />);

    // When
    await user.click(screen.getByRole("button", { name: /report/i }));
    await user.click(
      await screen.findByRole("menuitem", { name: /download latest/i }),
    );

    // Then
    await waitFor(() => expect(downloadPdfMock).toHaveBeenCalledWith("task-8"));
  });

  it("switches to the cross-account plumbing when providerType is set", async () => {
    // Given
    generateAccountPdfMock.mockResolvedValue({ taskId: "task-acc-1" });
    const user = userEvent.setup();
    render(<CrossProviderPdfButton {...props} providerType="aws" />);

    // When
    await openGenerateModal(user);
    await user.click(screen.getByRole("button", { name: /^generate$/i }));

    // Then — the cross-account action and task kind are used, not the
    // cross-provider ones.
    await waitFor(() =>
      expect(generateAccountPdfMock).toHaveBeenCalledTimes(1),
    );
    expect(generateAccountPdfMock).toHaveBeenCalledWith({
      complianceId: "csa_ccm_4.0",
      providerType: "aws",
      filters: props.filters,
      reportName: undefined,
    });
    expect(generatePdfMock).not.toHaveBeenCalled();
    expect(trackAndPollMock).toHaveBeenCalledWith({
      taskId: "task-acc-1",
      kind: "cross-account-pdf",
      meta: expect.objectContaining({ scopeKey: "account-scope-1" }),
    });
  });

  it("downloads the latest report through the cross-account action", async () => {
    const user = userEvent.setup();
    render(
      <CrossProviderPdfButton
        {...props}
        providerType="aws"
        latestPdf={{ taskId: "task-acc-7", filename: "aws-latest.pdf" }}
      />,
    );

    await user.click(screen.getByRole("button", { name: /report/i }));
    await user.click(
      await screen.findByRole("menuitem", { name: /download latest/i }),
    );

    await waitFor(() =>
      expect(downloadAccountPdfMock).toHaveBeenCalledWith("task-acc-7"),
    );
    expect(downloadPdfMock).not.toHaveBeenCalled();
  });

  it("does not offer a completed report from a different filter scope", async () => {
    // Given
    storeState.tasks = {
      "task-other-scope": {
        taskId: "task-other-scope",
        kind: "cross-provider-pdf",
        status: "ready",
        meta: {
          complianceId: "csa_ccm_4.0",
          scopeKey: "another-scope",
        },
        startedAt: Date.now(),
      },
    };
    const user = userEvent.setup();
    render(<CrossProviderPdfButton {...props} />);

    // When
    await user.click(screen.getByRole("button", { name: /report/i }));

    // Then
    expect(
      screen.queryByRole("menuitem", { name: /download latest/i }),
    ).not.toBeInTheDocument();
  });
});
