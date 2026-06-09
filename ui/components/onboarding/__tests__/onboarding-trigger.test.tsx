import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";
import type { OnboardingSequenceMode } from "@/store/onboarding-sequence";

import { OnboardingTrigger } from "../onboarding-trigger";

const startMock = vi.fn();
const pushMock = vi.fn();
const advanceMock = vi.fn();
const stopMock = vi.fn();

// Counts hook re-invocations; the regression test uses this to confirm the runner stays mounted.
const useDriverTourMock = vi.fn();
// Captures onClosed so close→action wiring can be exercised without driver.js.
let capturedOnClosed: ((state: string) => void) | undefined;

let searchParamsValue = new URLSearchParams();

let sliceState = {
  active: false,
  currentFlowId: null as string | null,
  mode: null as OnboardingSequenceMode | null,
  advance: advanceMock,
  stop: stopMock,
};

vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParamsValue,
  usePathname: () => "/providers",
  useRouter: () => ({ replace: vi.fn(), push: pushMock }),
}));

vi.mock("@/lib/tours/use-driver-tour", () => ({
  useDriverTour: (
    _tour: unknown,
    options: { onClosed?: (state: string) => void },
  ) => {
    useDriverTourMock();
    capturedOnClosed = options?.onClosed;
    return { start: startMock, stop: vi.fn(), hasCompleted: false };
  },
}));

vi.mock("@/store/onboarding-sequence", () => {
  const hook = (selector: (state: typeof sliceState) => unknown) =>
    selector(sliceState);
  hook.getState = () => sliceState;
  return { useOnboardingSequenceStore: hook };
});

const addProviderFlow = getFlowById("add-provider")!;

function setSlice(next: Partial<typeof sliceState>) {
  sliceState = { ...sliceState, ...next };
}

describe("OnboardingTrigger", () => {
  beforeEach(() => {
    startMock.mockClear();
    pushMock.mockClear();
    advanceMock.mockClear();
    stopMock.mockClear();
    useDriverTourMock.mockClear();
    capturedOnClosed = undefined;
    // Trigger only resolves in cloud.
    vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "true");
    searchParamsValue = new URLSearchParams();
    sliceState = {
      active: false,
      currentFlowId: null,
      mode: null,
      advance: advanceMock,
      stop: stopMock,
    };
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the onboarding param matches this flow (replay)", () => {
    it("force-starts the tour and strips the param", async () => {
      searchParamsValue = new URLSearchParams("onboarding=add-provider");
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      render(<OnboardingTrigger flow={addProviderFlow} />);

      // Param is stripped via history.replaceState (no router round-trip).
      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));
      await waitFor(() =>
        expect(replaceStateSpy).toHaveBeenCalledWith(
          null,
          "",
          window.location.pathname,
        ),
      );
    });

    it("strips only the onboarding param and preserves other query params", async () => {
      searchParamsValue = new URLSearchParams(
        "scanId=scan-1&onboarding=add-provider&tab=completed",
      );
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      render(<OnboardingTrigger flow={addProviderFlow} />);

      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));
      await waitFor(() =>
        expect(replaceStateSpy).toHaveBeenCalledWith(
          null,
          "",
          `${window.location.pathname}?scanId=scan-1&tab=completed`,
        ),
      );
    });
  });

  describe("when the sequence names this flow", () => {
    it("force-starts the tour without stripping any param", async () => {
      setSlice({
        active: true,
        currentFlowId: "add-provider",
        mode: "sequence",
      });
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      render(<OnboardingTrigger flow={addProviderFlow} />);

      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));
      expect(replaceStateSpy).not.toHaveBeenCalled();
    });
  });

  describe("when neither the param nor the sequence names this flow", () => {
    it("renders null and does not start the tour", async () => {
      searchParamsValue = new URLSearchParams();
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      const { container } = render(
        <OnboardingTrigger flow={addProviderFlow} />,
      );

      expect(container).toBeEmptyDOMElement();
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
      expect(replaceStateSpy).not.toHaveBeenCalled();
    });
  });

  describe("when the onboarding param targets a different flow", () => {
    it("does not start the tour", async () => {
      searchParamsValue = new URLSearchParams("onboarding=explore-findings");

      render(<OnboardingTrigger flow={addProviderFlow} />);

      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
    });
  });

  describe("in self-hosted (OSS) deployments", () => {
    it("renders null and never starts the tour, even with a matching param", async () => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
      searchParamsValue = new URLSearchParams("onboarding=add-provider");

      const { container } = render(
        <OnboardingTrigger flow={addProviderFlow} />,
      );

      expect(container).toBeEmptyDOMElement();
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
    });

    it("ignores an active sequence slice in OSS", async () => {
      vi.stubEnv("NEXT_PUBLIC_IS_CLOUD_ENV", "false");
      setSlice({
        active: true,
        currentFlowId: "add-provider",
        mode: "sequence",
      });

      const { container } = render(
        <OnboardingTrigger flow={addProviderFlow} />,
      );

      expect(container).toBeEmptyDOMElement();
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
    });
  });

  describe("when a sequence tour completes", () => {
    it("leaves the sequence slice untouched (the banner owns advance now)", async () => {
      setSlice({
        active: true,
        currentFlowId: "add-provider",
        mode: "sequence",
      });

      render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(capturedOnClosed).toBeDefined());
      capturedOnClosed?.("completed");

      // Banner is the sole advance/exit control; closing the tour must not auto-advance.
      expect(advanceMock).not.toHaveBeenCalled();
      expect(stopMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
    });
  });

  describe("when a sequence tour is dismissed", () => {
    it("leaves the sequence slice untouched (no auto-stop on close)", async () => {
      setSlice({
        active: true,
        currentFlowId: "add-provider",
        mode: "sequence",
      });

      render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(capturedOnClosed).toBeDefined());
      capturedOnClosed?.("skipped");

      // Only the banner Exit button ends the sequence; closing the tour must not auto-stop.
      expect(stopMock).not.toHaveBeenCalled();
      expect(advanceMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
    });
  });

  describe("when a replay tour closes", () => {
    it("does not touch the sequence slice", async () => {
      searchParamsValue = new URLSearchParams("onboarding=add-provider");

      render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(capturedOnClosed).toBeDefined());
      capturedOnClosed?.("completed");

      // Single-flow replay never advances or stops the sequence.
      expect(advanceMock).not.toHaveBeenCalled();
      expect(stopMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
    });
  });

  describe("when the param is cleared after the tour starts (regression)", () => {
    it("keeps the runner mounted and does not restart the tour", async () => {
      // StrictMode-safe latch: stripping the param must not unmount the runner or re-start the tour.
      searchParamsValue = new URLSearchParams("onboarding=add-provider");
      const { rerender } = render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));

      const callsBeforeClear = useDriverTourMock.mock.calls.length;

      searchParamsValue = new URLSearchParams();
      rerender(<OnboardingTrigger flow={addProviderFlow} />);

      await waitFor(() =>
        expect(useDriverTourMock.mock.calls.length).toBeGreaterThan(
          callsBeforeClear,
        ),
      );
      expect(startMock).toHaveBeenCalledTimes(1);
    });
  });
});
