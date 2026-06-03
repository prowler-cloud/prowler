import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";

import { OnboardingSequenceBanner } from "../onboarding-sequence-banner";

const pushMock = vi.fn();
const advanceMock = vi.fn();
const stopMock = vi.fn();

// Mutable sequence-slice snapshot the mocked store hook returns. The banner
// reads `active` + `currentFlowId` reactively and calls advance/stop via
// getState(), mirroring the trigger's store usage.
let sliceState = {
  active: false,
  currentFlowId: null as string | null,
  advance: advanceMock,
  stop: stopMock,
};

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/store/onboarding-sequence", () => {
  const hook = (selector: (state: typeof sliceState) => unknown) =>
    selector(sliceState);
  hook.getState = () => sliceState;
  return { useOnboardingSequenceStore: hook };
});

function setSlice(next: Partial<typeof sliceState>) {
  sliceState = { ...sliceState, ...next };
}

describe("OnboardingSequenceBanner", () => {
  beforeEach(() => {
    pushMock.mockClear();
    advanceMock.mockClear();
    stopMock.mockClear();
    sliceState = {
      active: false,
      currentFlowId: null,
      advance: advanceMock,
      stop: stopMock,
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders nothing when the sequence is inactive", () => {
    // Given - the sequence slice is not active
    // When
    const { container } = render(<OnboardingSequenceBanner />);

    // Then - the banner self-hides
    expect(container).toBeEmptyDOMElement();
  });

  it("shows the step progress for the active flow", () => {
    // Given - the sequence points at the second ordered flow (view-first-scan)
    setSlice({ active: true, currentFlowId: "view-first-scan" });
    const flow = getFlowById("view-first-scan")!;

    // When
    render(<OnboardingSequenceBanner />);

    // Then - "Step 2 of 5: Run your first scan"
    expect(screen.getByText(`Step 2 of 5: ${flow.title}`)).toBeInTheDocument();
  });

  it("announces step progress to screen readers via a polite live region", () => {
    // Given - the sequence points at an active flow
    setSlice({ active: true, currentFlowId: "view-first-scan" });
    const flow = getFlowById("view-first-scan")!;

    // When
    render(<OnboardingSequenceBanner />);

    // Then - the step-progress text is a polite live region so screen readers
    // announce step transitions when the banner text updates.
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent(`Step 2 of 5: ${flow.title}`);
    expect(status).toHaveAttribute("aria-live", "polite");
  });

  it("shows the data requirement hint when the current flow has one", () => {
    // Given - explore-findings carries the scan-data hint
    setSlice({ active: true, currentFlowId: "explore-findings" });

    // When
    render(<OnboardingSequenceBanner />);

    // Then - the hint is visible in the banner
    expect(
      screen.getByText(/needs a completed scan to show data/i),
    ).toBeInTheDocument();
  });

  it("does not show a hint for a flow without one", () => {
    // Given - view-first-scan has no data requirement hint
    setSlice({ active: true, currentFlowId: "view-first-scan" });

    // When
    render(<OnboardingSequenceBanner />);

    // Then - no scan-data hint is rendered
    expect(
      screen.queryByText(/needs a completed scan to show data/i),
    ).not.toBeInTheDocument();
  });

  it("advances and navigates to the next flow when Continue is clicked", async () => {
    // Given - the sequence is on view-first-scan; next is explore-findings
    setSlice({ active: true, currentFlowId: "view-first-scan" });
    const nextFlow = getFlowById("explore-findings")!;
    const user = userEvent.setup();

    // When
    render(<OnboardingSequenceBanner />);
    await user.click(screen.getByRole("button", { name: /continue/i }));

    // Then - advance the slice and push to the next flow's route
    expect(advanceMock).toHaveBeenCalledTimes(1);
    expect(pushMock).toHaveBeenCalledWith(nextFlow.route);
    expect(stopMock).not.toHaveBeenCalled();
  });

  it("stops the sequence without navigating when Continue is clicked on the last step", async () => {
    // Given - the sequence is on the final ordered flow (attack-paths)
    setSlice({ active: true, currentFlowId: "attack-paths" });
    const user = userEvent.setup();

    // When
    render(<OnboardingSequenceBanner />);
    await user.click(screen.getByRole("button", { name: /continue/i }));

    // Then - the sequence ends and no navigation occurs
    expect(stopMock).toHaveBeenCalledTimes(1);
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("stops the sequence when Exit is clicked", async () => {
    // Given - the sequence is active mid-way
    setSlice({ active: true, currentFlowId: "explore-findings" });
    const user = userEvent.setup();

    // When
    render(<OnboardingSequenceBanner />);
    await user.click(screen.getByRole("button", { name: /exit/i }));

    // Then - the sequence ends without advancing or navigating
    expect(stopMock).toHaveBeenCalledTimes(1);
    expect(advanceMock).not.toHaveBeenCalled();
    expect(pushMock).not.toHaveBeenCalled();
  });
});
