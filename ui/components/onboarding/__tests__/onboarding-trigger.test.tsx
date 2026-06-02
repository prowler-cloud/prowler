import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";

import { OnboardingTrigger } from "../onboarding-trigger";

const startMock = vi.fn();
const pushMock = vi.fn();
const advanceMock = vi.fn();
const stopMock = vi.fn();

// Counts every `useDriverTour` invocation. A mounted runner re-invokes the hook
// on each render; an unmounted runner never invokes it again. This is the
// signal the regression test reads.
const useDriverTourMock = vi.fn();
// Captures the `onClosed` callback the runner passes to `useDriverTour`, so the
// close→action wiring can be exercised without driver.js (the hook short-
// circuits under NODE_ENV==="test").
let capturedOnClosed: ((state: string) => void) | undefined;

let searchParamsValue = new URLSearchParams();

// Mutable sequence-slice snapshot the mocked store hook returns.
let sliceState = {
  active: false,
  currentFlowId: null as string | null,
  mode: null as "sequence" | "replay" | null,
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
  // The runner's `onClosed` reads `getState()` for the imperative advance/stop.
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
      // Given - the URL carries ?onboarding=add-provider
      searchParamsValue = new URLSearchParams("onboarding=add-provider");
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      // When - the trigger mounts
      render(<OnboardingTrigger flow={addProviderFlow} />);

      // Then - it starts the tour and strips the param (preserving pathname)
      // without a router round-trip.
      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));
      await waitFor(() =>
        expect(replaceStateSpy).toHaveBeenCalledWith(
          null,
          "",
          window.location.pathname,
        ),
      );
    });
  });

  describe("when the sequence names this flow", () => {
    it("force-starts the tour without stripping any param", async () => {
      // Given - the sequence is active and points at this route's flow
      setSlice({
        active: true,
        currentFlowId: "add-provider",
        mode: "sequence",
      });
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      // When - the trigger mounts
      render(<OnboardingTrigger flow={addProviderFlow} />);

      // Then - it starts the tour and does NOT touch the URL (no replay param)
      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));
      expect(replaceStateSpy).not.toHaveBeenCalled();
    });
  });

  describe("when neither the param nor the sequence names this flow", () => {
    it("renders null and does not start the tour", async () => {
      // Given - a bare URL and an inactive sequence
      searchParamsValue = new URLSearchParams();
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      // When - the trigger mounts
      const { container } = render(
        <OnboardingTrigger flow={addProviderFlow} />,
      );

      // Then - nothing renders and nothing starts
      expect(container).toBeEmptyDOMElement();
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
      expect(replaceStateSpy).not.toHaveBeenCalled();
    });
  });

  describe("when the onboarding param targets a different flow", () => {
    it("does not start the tour", async () => {
      // Given - the param names another flow and the sequence is inactive
      searchParamsValue = new URLSearchParams("onboarding=explore-findings");

      // When - the trigger mounts for the add-provider flow
      render(<OnboardingTrigger flow={addProviderFlow} />);

      // Then - this trigger stays inert
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
    });
  });

  describe("when a sequence tour completes", () => {
    it("leaves the sequence slice untouched (the banner owns advance now)", async () => {
      // Given - the sequence is on add-provider
      setSlice({
        active: true,
        currentFlowId: "add-provider",
        mode: "sequence",
      });

      // When - the trigger mounts and the tour finishes on its last step
      render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(capturedOnClosed).toBeDefined());
      capturedOnClosed?.("completed");

      // Then - closing the tour no longer auto-advances or navigates. The
      // persistent banner is the only advance/exit control: the user stays on
      // the page until they explicitly click Continue.
      expect(advanceMock).not.toHaveBeenCalled();
      expect(stopMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
    });
  });

  describe("when a sequence tour is dismissed", () => {
    it("leaves the sequence slice untouched (no auto-stop on close)", async () => {
      // Given - the sequence is on add-provider
      setSlice({
        active: true,
        currentFlowId: "add-provider",
        mode: "sequence",
      });

      // When - the trigger mounts and the user closes the tour mid-way
      render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(capturedOnClosed).toBeDefined());
      capturedOnClosed?.("skipped");

      // Then - closing leaves the sequence active; only the banner Exit ends it
      expect(stopMock).not.toHaveBeenCalled();
      expect(advanceMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
    });
  });

  describe("when a replay tour closes", () => {
    it("does not touch the sequence slice", async () => {
      // Given - a replay request via the param (sequence inactive)
      searchParamsValue = new URLSearchParams("onboarding=add-provider");

      // When - the trigger mounts and the replay tour closes
      render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(capturedOnClosed).toBeDefined());
      capturedOnClosed?.("completed");

      // Then - single-flow replay never advances or stops the sequence
      expect(advanceMock).not.toHaveBeenCalled();
      expect(stopMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
    });
  });

  describe("when the param is cleared after the tour starts (regression)", () => {
    it("keeps the runner mounted and does not restart the tour", async () => {
      // Given - the URL carries ?onboarding=add-provider and the tour starts
      searchParamsValue = new URLSearchParams("onboarding=add-provider");
      const { rerender } = render(<OnboardingTrigger flow={addProviderFlow} />);
      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));

      const callsBeforeClear = useDriverTourMock.mock.calls.length;

      // When - the onboarding param is stripped and the component re-renders
      searchParamsValue = new URLSearchParams();
      rerender(<OnboardingTrigger flow={addProviderFlow} />);

      // Then - the runner stays mounted (re-invokes the hook) and the tour is
      // not started a second time. This is the StrictMode-safe latch regression
      // guard carried over from ProvidersOnboardingTrigger.
      await waitFor(() =>
        expect(useDriverTourMock.mock.calls.length).toBeGreaterThan(
          callsBeforeClear,
        ),
      );
      expect(startMock).toHaveBeenCalledTimes(1);
    });
  });
});
