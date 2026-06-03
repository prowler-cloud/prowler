import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ProvidersOnboardingTrigger } from "../providers-onboarding-trigger";

const startMock = vi.fn();
const replaceMock = vi.fn();
// Counts every `useDriverTour` invocation. A mounted runner re-invokes the
// hook on each render; an unmounted runner never invokes it again. This is the
// signal the unmount-regression test reads.
const useDriverTourMock = vi.fn();
let searchParamsValue = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParamsValue,
  usePathname: () => "/providers",
  useRouter: () => ({ replace: replaceMock, push: vi.fn() }),
}));

vi.mock("@/lib/tours/use-driver-tour", () => ({
  useDriverTour: () => {
    useDriverTourMock();
    return {
      start: startMock,
      stop: vi.fn(),
      hasCompleted: false,
    };
  },
}));

describe("ProvidersOnboardingTrigger", () => {
  beforeEach(() => {
    startMock.mockClear();
    replaceMock.mockClear();
    useDriverTourMock.mockClear();
    searchParamsValue = new URLSearchParams();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the onboarding param matches a known flow", () => {
    it("force-starts the tour and clears the param", async () => {
      // Given - the URL carries ?onboarding=add-provider
      searchParamsValue = new URLSearchParams("onboarding=add-provider");
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      // When - the trigger mounts
      render(<ProvidersOnboardingTrigger openWizard={vi.fn()} />);

      // Then - it starts the tour and strips the param (preserving the current
      // pathname) to avoid a reload loop, without a router round-trip.
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

  describe("when there is no onboarding param", () => {
    it("does not start the tour", async () => {
      // Given - a bare URL
      searchParamsValue = new URLSearchParams();
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      // When - the trigger mounts
      render(<ProvidersOnboardingTrigger openWizard={vi.fn()} />);

      // Then - nothing is triggered
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
      expect(replaceStateSpy).not.toHaveBeenCalled();
    });
  });

  describe("when the onboarding param does not match a known flow", () => {
    it("does not start the tour", async () => {
      // Given - an unknown flow id in the URL
      searchParamsValue = new URLSearchParams("onboarding=unknown-xyz");
      const replaceStateSpy = vi.spyOn(window.history, "replaceState");

      // When - the trigger mounts
      render(<ProvidersOnboardingTrigger openWizard={vi.fn()} />);

      // Then - nothing is triggered
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
      expect(replaceStateSpy).not.toHaveBeenCalled();
    });
  });

  describe("when the param is cleared after the tour starts", () => {
    it("keeps the tour runner mounted and does not restart the tour", async () => {
      // Given - the URL carries ?onboarding=add-provider and the tour starts
      searchParamsValue = new URLSearchParams("onboarding=add-provider");
      const { rerender } = render(
        <ProvidersOnboardingTrigger openWizard={vi.fn()} />,
      );
      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));

      const callsBeforeClear = useDriverTourMock.mock.calls.length;

      // When - the onboarding param is stripped from the URL (as happens after
      // the trigger clears it) and the component re-renders
      searchParamsValue = new URLSearchParams();
      rerender(<ProvidersOnboardingTrigger openWizard={vi.fn()} />);

      // Then - the runner stays mounted (the latched flow is not torn down) and
      // the tour is not started a second time. This is the regression guard:
      // the old code derived `flow` from the live param and UNMOUNTED the
      // runner here (destroying the just-started tour). A mounted runner
      // re-invokes `useDriverTour` on the re-render; an unmounted one never
      // would.
      await waitFor(() =>
        expect(useDriverTourMock.mock.calls.length).toBeGreaterThan(
          callsBeforeClear,
        ),
      );
      expect(startMock).toHaveBeenCalledTimes(1);
    });
  });
});
