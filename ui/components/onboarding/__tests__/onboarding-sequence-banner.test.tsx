import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";

import { OnboardingSequenceBanner } from "../onboarding-sequence-banner";

const pushMock = vi.fn();
const advanceMock = vi.fn();
const stopMock = vi.fn();
const goToFlowMock = vi.fn();

// Mutable snapshot the mocked store hook returns; tests mutate via setSlice().
let sliceState = {
  active: false,
  currentFlowId: null as string | null,
  advance: advanceMock,
  stop: stopMock,
  goToFlow: goToFlowMock,
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
    goToFlowMock.mockClear();
    sliceState = {
      active: false,
      currentFlowId: null,
      advance: advanceMock,
      stop: stopMock,
      goToFlow: goToFlowMock,
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("renders nothing when the sequence is inactive", () => {
    const { container } = render(<OnboardingSequenceBanner />);

    expect(container).toBeEmptyDOMElement();
  });

  it("shows the step progress for the active flow", () => {
    setSlice({ active: true, currentFlowId: "view-first-scan" });
    const flow = getFlowById("view-first-scan")!;

    render(<OnboardingSequenceBanner />);

    expect(screen.getByText(`Step 2 of 5: ${flow.title}`)).toBeInTheDocument();
  });

  it("announces step progress to screen readers via a polite live region", () => {
    setSlice({ active: true, currentFlowId: "view-first-scan" });
    const flow = getFlowById("view-first-scan")!;

    render(<OnboardingSequenceBanner />);

    // Polite live region so screen readers announce step transitions on update.
    const status = screen.getByRole("status");
    expect(status).toHaveTextContent(`Step 2 of 5: ${flow.title}`);
    expect(status).toHaveAttribute("aria-live", "polite");
  });

  it("shows the data requirement hint when the current flow has one", () => {
    setSlice({ active: true, currentFlowId: "explore-findings" });

    render(<OnboardingSequenceBanner />);

    expect(
      screen.getByText(/this step needs scan results to show data/i),
    ).toBeInTheDocument();
  });

  it("does not show a hint for a flow without one", () => {
    setSlice({ active: true, currentFlowId: "view-first-scan" });

    render(<OnboardingSequenceBanner />);

    expect(
      screen.queryByText(/needs a completed scan to show data/i),
    ).not.toBeInTheDocument();
  });

  it("advances and navigates to the next flow when Continue is clicked", async () => {
    setSlice({ active: true, currentFlowId: "view-first-scan" });
    const nextFlow = getFlowById("explore-findings")!;
    const user = userEvent.setup();

    render(<OnboardingSequenceBanner />);
    await user.click(screen.getByRole("button", { name: /continue/i }));

    expect(advanceMock).toHaveBeenCalledTimes(1);
    expect(pushMock).toHaveBeenCalledWith(nextFlow.route);
    expect(stopMock).not.toHaveBeenCalled();
  });

  it("stops the sequence without navigating when Continue is clicked on the last step", async () => {
    setSlice({ active: true, currentFlowId: "attack-paths" });
    const user = userEvent.setup();

    render(<OnboardingSequenceBanner />);
    await user.click(screen.getByRole("button", { name: /continue/i }));

    expect(stopMock).toHaveBeenCalledTimes(1);
    expect(pushMock).not.toHaveBeenCalled();
  });

  it("offers a Run a scan shortcut when the flow needs scan data and none is completed", () => {
    setSlice({ active: true, currentFlowId: "explore-findings" });

    render(<OnboardingSequenceBanner hasCompletedScan={false} />);

    expect(
      screen.getByRole("button", { name: /run a scan/i }),
    ).toBeInTheDocument();
  });

  it("hides the Run a scan shortcut once a scan has completed", () => {
    setSlice({ active: true, currentFlowId: "explore-findings" });

    render(<OnboardingSequenceBanner hasCompletedScan={true} />);

    expect(
      screen.queryByRole("button", { name: /run a scan/i }),
    ).not.toBeInTheDocument();
  });

  it("does not offer the Run a scan shortcut for a flow without a data hint", () => {
    setSlice({ active: true, currentFlowId: "add-provider" });

    render(<OnboardingSequenceBanner hasCompletedScan={false} />);

    expect(
      screen.queryByRole("button", { name: /run a scan/i }),
    ).not.toBeInTheDocument();
  });

  it("does not offer the Run a scan shortcut on the scan flow itself", () => {
    // No shortcut when the user is already on the flow the shortcut navigates to.
    setSlice({ active: true, currentFlowId: "view-first-scan" });

    render(<OnboardingSequenceBanner hasCompletedScan={false} />);

    expect(
      screen.queryByRole("button", { name: /run a scan/i }),
    ).not.toBeInTheDocument();
  });

  it("jumps the banner to the scan step and navigates when Run a scan is clicked", async () => {
    setSlice({ active: true, currentFlowId: "explore-findings" });
    const scanFlow = getFlowById("view-first-scan")!;
    const user = userEvent.setup();

    render(<OnboardingSequenceBanner hasCompletedScan={false} />);
    await user.click(screen.getByRole("button", { name: /run a scan/i }));

    expect(goToFlowMock).toHaveBeenCalledWith(scanFlow.id);
    expect(pushMock).toHaveBeenCalledWith(scanFlow.route);
    expect(advanceMock).not.toHaveBeenCalled();
    expect(stopMock).not.toHaveBeenCalled();
  });

  it("still advances on Continue regardless of completed-scan state", async () => {
    // Continue is non-blocking even when the scan shortcut is visible.
    setSlice({ active: true, currentFlowId: "explore-findings" });
    const nextFlow = getFlowById("view-compliance")!;
    const user = userEvent.setup();

    render(<OnboardingSequenceBanner hasCompletedScan={false} />);
    await user.click(screen.getByRole("button", { name: /^continue$/i }));

    expect(advanceMock).toHaveBeenCalledTimes(1);
    expect(pushMock).toHaveBeenCalledWith(nextFlow.route);
    expect(goToFlowMock).not.toHaveBeenCalled();
  });

  it("stops the sequence when Exit is clicked", async () => {
    setSlice({ active: true, currentFlowId: "explore-findings" });
    const user = userEvent.setup();

    render(<OnboardingSequenceBanner />);
    await user.click(screen.getByRole("button", { name: /exit/i }));

    expect(stopMock).toHaveBeenCalledTimes(1);
    expect(advanceMock).not.toHaveBeenCalled();
    expect(pushMock).not.toHaveBeenCalled();
  });
});
