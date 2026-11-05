import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SAMPLE_PREVIEW_EVENT,
  SAMPLE_PREVIEW_PAGE,
  SAMPLE_PREVIEW_STEP,
} from "@/lib/sample-preview/sample-preview-events";
import { SAMPLE_PREVIEW_STAGE } from "@/lib/sample-preview/sample-preview-state";
import { LAUNCH_SCAN_HREF } from "@/lib/scans-navigation";

import {
  SAMPLE_PREVIEW_POLL_INTERVAL_MS,
  SamplePreviewBanner,
} from "./sample-preview-banner";

const { getScanMock, getCompletedScansMock, refreshMock } = vi.hoisted(() => ({
  getScanMock: vi.fn(),
  getCompletedScansMock: vi.fn(),
  refreshMock: vi.fn(),
}));

vi.mock("@/actions/scans", () => ({
  getScan: getScanMock,
  getScansByState: getCompletedScansMock,
}));
vi.mock("next/navigation", () => ({
  useRouter: () => ({ refresh: refreshMock }),
}));

const RUNNING = {
  active: true as const,
  stage: SAMPLE_PREVIEW_STAGE.SCAN_RUNNING,
  runningScan: { id: "scan-1", progress: 10 },
};

const scanResponse = (state: string, progress: number) => ({
  data: { id: "scan-1", attributes: { state, progress } },
});

const advancePoll = () =>
  act(async () => {
    await vi.advanceTimersByTimeAsync(SAMPLE_PREVIEW_POLL_INTERVAL_MS);
  });

describe("SamplePreviewBanner", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    getCompletedScansMock.mockResolvedValue({ data: [] });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("points a tenant without providers at the add-provider wizard", () => {
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={{
          active: true,
          stage: SAMPLE_PREVIEW_STAGE.NO_PROVIDER,
          runningScan: null,
        }}
      />,
    );

    expect(screen.getByText("You are exploring sample data")).toBeVisible();
    expect(screen.getByRole("link", { name: "Add Provider" })).toHaveAttribute(
      "href",
      expect.stringContaining("addProviderSource=sample_preview"),
    );
  });

  it("shows the running scan's progress as it advances", async () => {
    getScanMock.mockResolvedValue(scanResponse("executing", 57));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );
    expect(screen.getByText("10%")).toBeVisible();

    await advancePoll();

    expect(screen.getByText("57%")).toBeVisible();
    expect(refreshMock).not.toHaveBeenCalled();
  });

  it("swaps in the real data when the first scan completes", async () => {
    getScanMock.mockResolvedValue(scanResponse("completed", 100));
    const events: string[] = [];
    const listener = (event: Event) =>
      events.push((event as CustomEvent<{ step: string }>).detail.step);
    window.addEventListener(SAMPLE_PREVIEW_EVENT, listener);
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    await advancePoll();
    await advancePoll();

    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(events).toEqual([
      SAMPLE_PREVIEW_STEP.VIEWED,
      SAMPLE_PREVIEW_STEP.EXITED,
    ]);
    window.removeEventListener(SAMPLE_PREVIEW_EVENT, listener);
  });

  it("exits when another scan completes before the tracked scan", async () => {
    // Given: the newest scan is still running, but an earlier scan finished.
    getScanMock.mockResolvedValue(scanResponse("executing", 30));
    getCompletedScansMock.mockResolvedValue({ data: [{ id: "earlier-scan" }] });
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    // When
    await advancePoll();
    await advancePoll();

    // Then: refresh once and stop polling the unfinished scan.
    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(getScanMock).toHaveBeenCalledTimes(1);
  });

  it("re-resolves the page when the tracked scan is gone", async () => {
    getScanMock.mockResolvedValue({ error: "Not found", status: 404 });
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    await advancePoll();
    await advancePoll();

    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(getScanMock).toHaveBeenCalledTimes(1);
  });

  it("keeps polling through a transient empty response", async () => {
    getScanMock
      .mockResolvedValueOnce(undefined)
      .mockResolvedValue(scanResponse("completed", 100));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    await advancePoll();
    expect(refreshMock).not.toHaveBeenCalled();

    await advancePoll();
    expect(refreshMock).toHaveBeenCalledTimes(1);
  });

  it("skips a poll while the previous request is still pending", async () => {
    getScanMock.mockReturnValue(new Promise(() => {}));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    await advancePoll();
    await advancePoll();

    expect(getScanMock).toHaveBeenCalledTimes(1);
  });

  it("points a tenant with a provider but no scan at launching one", () => {
    // Given / When
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.FINDINGS}
        state={{
          active: true,
          stage: SAMPLE_PREVIEW_STAGE.NO_SCAN,
          runningScan: null,
        }}
      />,
    );

    // Then
    expect(screen.getByRole("link", { name: "Launch Scan" })).toHaveAttribute(
      "href",
      LAUNCH_SCAN_HREF,
    );
    expect(screen.queryByLabelText("First scan progress")).toBeNull();
  });

  it("goes back to the no-scan stage when the first scan fails", async () => {
    // Given
    getScanMock.mockResolvedValue(scanResponse("failed", 30));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    // When
    await advancePoll();
    await advancePoll();

    // Then
    expect(refreshMock).toHaveBeenCalledTimes(1);
    expect(getScanMock).toHaveBeenCalledTimes(1);
  });

  it("keeps polling when a progress request fails", async () => {
    // Given
    getScanMock
      .mockRejectedValueOnce(new Error("Network error"))
      .mockResolvedValue(scanResponse("executing", 70));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    // When
    await advancePoll();
    await advancePoll();

    // Then
    expect(screen.getByText("70%")).toBeVisible();
  });

  it("keeps progress updates and completion working when the completed-scan lookup fails", async () => {
    getCompletedScansMock.mockRejectedValue(new Error("Network error"));
    getScanMock
      .mockResolvedValueOnce(scanResponse("executing", 70))
      .mockResolvedValue(scanResponse("completed", 100));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    await advancePoll();
    expect(screen.getByText("70%")).toBeVisible();
    expect(refreshMock).not.toHaveBeenCalled();

    await advancePoll();
    expect(refreshMock).toHaveBeenCalledTimes(1);
  });

  it("tells a running scan apart and opens the in-progress scans tab", () => {
    getScanMock.mockReturnValue(new Promise(() => {}));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    expect(
      screen.getByText("You're seeing sample data until your scan finishes"),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: "View Running Scans" }),
    ).toHaveAttribute("href", "/scans?tab=active");
  });

  it("updates the tracked scan without waiting for the completed-scan lookup", async () => {
    // Given: the completed-scan lookup never answers.
    getCompletedScansMock.mockReturnValue(new Promise(() => {}));
    getScanMock.mockResolvedValue(scanResponse("executing", 45));
    render(
      <SamplePreviewBanner
        page={SAMPLE_PREVIEW_PAGE.OVERVIEW}
        state={RUNNING}
      />,
    );

    // When
    await advancePoll();
    getScanMock.mockResolvedValue(scanResponse("executing", 60));
    await advancePoll();

    // Then: later polls keep tracking the scan while the lookup is pending.
    expect(screen.getByText("60%")).toBeVisible();
    expect(getScanMock).toHaveBeenCalledTimes(2);
    expect(getCompletedScansMock).toHaveBeenCalledTimes(1);
  });
});
