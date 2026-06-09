import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";

import { OnboardingSequenceBanner } from "../onboarding-sequence-banner";

const pushMock = vi.fn();
const advanceMock = vi.fn();
const stopMock = vi.fn();

// Mutable snapshot the mocked store hook returns; tests mutate via setSlice().
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

  it("does not show the data requirement hint on a scan-dependent step once a scan has finished", () => {
    // The Continue gate already guarantees we only reach this step with data,
    // so the "wait for findings" hint would be stale/misleading here.
    setSlice({ active: true, currentFlowId: "explore-findings" });

    render(<OnboardingSequenceBanner hasCompletedScan={true} />);

    expect(
      screen.queryByText(/wait for the scan to finish/i),
    ).not.toBeInTheDocument();
  });

  it("does not show a hint for a flow without one", () => {
    setSlice({ active: true, currentFlowId: "view-first-scan" });

    render(<OnboardingSequenceBanner />);

    expect(
      screen.queryByText(/wait for the scan to finish/i),
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

  it("stops the sequence when Skip is clicked", async () => {
    setSlice({ active: true, currentFlowId: "explore-findings" });
    const user = userEvent.setup();

    render(<OnboardingSequenceBanner />);
    await user.click(screen.getByRole("button", { name: /skip/i }));

    expect(stopMock).toHaveBeenCalledTimes(1);
    expect(advanceMock).not.toHaveBeenCalled();
    expect(pushMock).not.toHaveBeenCalled();
  });

  describe("scan-gated Continue", () => {
    it("disables Continue when the next step needs scan data and none has finished", () => {
      // On the scan step, advancing would land on explore-findings (scan-dependent).
      setSlice({ active: true, currentFlowId: "view-first-scan" });

      render(<OnboardingSequenceBanner hasCompletedScan={false} />);

      expect(screen.getByRole("button", { name: /continue/i })).toBeDisabled();
      // The next step's hint explains why progression is blocked.
      expect(
        screen.getByText(/wait for the scan to finish/i),
      ).toBeInTheDocument();
    });

    it("does not advance even if a disabled Continue is force-clicked", async () => {
      setSlice({ active: true, currentFlowId: "view-first-scan" });
      const user = userEvent.setup();

      render(<OnboardingSequenceBanner hasCompletedScan={false} />);
      await user.click(screen.getByRole("button", { name: /continue/i }));

      expect(advanceMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
    });

    it("enables Continue once a scan has finished", () => {
      setSlice({ active: true, currentFlowId: "view-first-scan" });

      render(<OnboardingSequenceBanner hasCompletedScan={true} />);

      expect(screen.getByRole("button", { name: /continue/i })).toBeEnabled();
    });

    it("surfaces the hint on a scan-dependent step itself when no scan has finished", () => {
      // Edge case: if we somehow sit on findings without a completed scan, the
      // next step (compliance) is still gated, so the hint explains the block.
      setSlice({ active: true, currentFlowId: "explore-findings" });

      render(<OnboardingSequenceBanner hasCompletedScan={false} />);

      expect(screen.getByRole("button", { name: /continue/i })).toBeDisabled();
      expect(
        screen.getByText(/wait for the scan to finish/i),
      ).toBeInTheDocument();
    });

    it("never gates Continue when the next step does not need scan data", () => {
      // add-provider → view-first-scan: neither requires scan data.
      setSlice({ active: true, currentFlowId: "add-provider" });

      render(<OnboardingSequenceBanner hasCompletedScan={false} />);

      expect(screen.getByRole("button", { name: /continue/i })).toBeEnabled();
    });
  });
});
