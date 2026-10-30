import { act, render, screen } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  SAMPLE_PREVIEW_EVENT,
  SAMPLE_PREVIEW_PAGE,
  SAMPLE_PREVIEW_STEP,
} from "@/lib/sample-preview/sample-preview-events";
import { SAMPLE_PREVIEW_STAGE } from "@/lib/sample-preview/sample-preview-state";

import {
  SAMPLE_PREVIEW_POLL_INTERVAL_MS,
  SamplePreviewBanner,
} from "./sample-preview-banner";

const { getScanMock, refreshMock } = vi.hoisted(() => ({
  getScanMock: vi.fn(),
  refreshMock: vi.fn(),
}));

vi.mock("@/actions/scans", () => ({ getScan: getScanMock }));
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
});
