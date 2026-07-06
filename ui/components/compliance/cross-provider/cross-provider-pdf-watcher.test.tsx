import { cleanup, render } from "@testing-library/react";
import type { ComponentProps } from "react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { useCrossProviderPdfStore } from "@/store/cross-provider-pdf/store";

import { CrossProviderPdfWatcher } from "./cross-provider-pdf-watcher";

const { getTaskMock, toastMock } = vi.hoisted(() => ({
  getTaskMock: vi.fn(),
  toastMock: vi.fn(),
}));

vi.mock("@/actions/task", () => ({
  getTask: getTaskMock,
}));

vi.mock("@/components/ui/toast", () => ({
  ToastAction: ({ children, ...props }: ComponentProps<"button">) => (
    <button {...props}>{children}</button>
  ),
  toast: toastMock,
}));

vi.mock("next/link", () => ({
  default: ({
    href,
    children,
  }: {
    href: string;
    children: React.ReactNode;
  }) => <a href={href}>{children}</a>,
}));

const POLL_INTERVAL_MS = 3000;

// Reset the (module-level) store between tests so tracked generations from
// one test never leak into the next.
const resetStore = () => useCrossProviderPdfStore.setState({ generations: {} });

describe("CrossProviderPdfWatcher", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    getTaskMock.mockReset();
    toastMock.mockReset();
    resetStore();
  });

  afterEach(() => {
    cleanup();
    vi.useRealTimers();
    resetStore();
  });

  it("fires the ready toast for a tracked generation even with no button mounted", async () => {
    getTaskMock.mockResolvedValue({
      data: { attributes: { state: "completed" } },
    });

    // The button is NOT rendered here — only the app-wide watcher. This is
    // exactly the "user navigated away from the generating page" case: the
    // notification must still arrive.
    render(<CrossProviderPdfWatcher />);

    useCrossProviderPdfStore.getState().trackGeneration({
      taskId: "task-123",
      signature: "csa_ccm_4.0|scan-1|||",
      reportUrl: "/compliance/csa_ccm_4.0?filter=x",
    });

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);

    expect(getTaskMock).toHaveBeenCalledWith("task-123");
    expect(toastMock).toHaveBeenCalledTimes(1);
    const payload = toastMock.mock.calls[0]?.[0];
    expect(payload.title).toBe("PDF report ready");
    // The action links back to the page the report was generated from.
    expect(payload.action.props.children.props.href).toBe(
      "/compliance/csa_ccm_4.0?filter=x",
    );
    // Completion is recorded so a still-mounted button can flip to Download.
    expect(
      useCrossProviderPdfStore.getState().generations["task-123"].status,
    ).toBe("completed");
  });

  it("keeps polling while the task is still running and does not toast", async () => {
    getTaskMock.mockResolvedValue({
      data: { attributes: { state: "executing" } },
    });
    render(<CrossProviderPdfWatcher />);

    useCrossProviderPdfStore.getState().trackGeneration({
      taskId: "task-run",
      signature: "sig",
      reportUrl: "/x",
    });

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 2);

    expect(getTaskMock).toHaveBeenCalled();
    expect(toastMock).not.toHaveBeenCalled();
    expect(
      useCrossProviderPdfStore.getState().generations["task-run"].status,
    ).toBe("running");
  });

  it("tolerates transient getTask errors and gives up only after several", async () => {
    getTaskMock.mockResolvedValue({ error: "boom" });
    render(<CrossProviderPdfWatcher />);

    useCrossProviderPdfStore.getState().trackGeneration({
      taskId: "task-err",
      signature: "sig",
      reportUrl: "/x",
    });

    // Two consecutive errors: still below the threshold — no failure toast.
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS * 2);
    expect(toastMock).not.toHaveBeenCalled();
    expect(
      useCrossProviderPdfStore.getState().generations["task-err"].status,
    ).toBe("running");

    // Third consecutive error crosses the threshold — fail and stop.
    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);
    expect(toastMock).toHaveBeenCalledTimes(1);
    expect(toastMock.mock.calls[0]?.[0].variant).toBe("destructive");
    expect(
      useCrossProviderPdfStore.getState().generations["task-err"].status,
    ).toBe("failed");
  });

  it("surfaces a terminal failure state with the task's error message", async () => {
    getTaskMock.mockResolvedValue({
      data: {
        attributes: { state: "failed", result: { error: "no scans" } },
      },
    });
    render(<CrossProviderPdfWatcher />);

    useCrossProviderPdfStore.getState().trackGeneration({
      taskId: "task-fail",
      signature: "sig",
      reportUrl: "/x",
    });

    await vi.advanceTimersByTimeAsync(POLL_INTERVAL_MS);

    expect(toastMock).toHaveBeenCalledTimes(1);
    const payload = toastMock.mock.calls[0]?.[0];
    expect(payload.variant).toBe("destructive");
    expect(payload.description).toContain("no scans");
    expect(
      useCrossProviderPdfStore.getState().generations["task-fail"].status,
    ).toBe("failed");
  });
});
