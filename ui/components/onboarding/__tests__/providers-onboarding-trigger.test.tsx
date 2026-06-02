import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ProvidersOnboardingTrigger } from "../providers-onboarding-trigger";

const startMock = vi.fn();
const replaceMock = vi.fn();
let searchParamsValue = new URLSearchParams();

vi.mock("next/navigation", () => ({
  useSearchParams: () => searchParamsValue,
  usePathname: () => "/providers",
  useRouter: () => ({ replace: replaceMock, push: vi.fn() }),
}));

vi.mock("@/lib/tours/use-driver-tour", () => ({
  useDriverTour: () => ({
    start: startMock,
    stop: vi.fn(),
    hasCompleted: false,
  }),
}));

describe("ProvidersOnboardingTrigger", () => {
  beforeEach(() => {
    startMock.mockClear();
    replaceMock.mockClear();
    searchParamsValue = new URLSearchParams();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the onboarding param matches a known flow", () => {
    it("force-starts the tour and clears the param", async () => {
      // Given - the URL carries ?onboarding=add-provider
      searchParamsValue = new URLSearchParams("onboarding=add-provider");

      // When - the trigger mounts
      render(<ProvidersOnboardingTrigger openWizard={vi.fn()} />);

      // Then - it starts the tour and strips the param to avoid a reload loop
      await waitFor(() => expect(startMock).toHaveBeenCalledTimes(1));
      await waitFor(() =>
        expect(replaceMock).toHaveBeenCalledWith("/providers"),
      );
    });
  });

  describe("when there is no onboarding param", () => {
    it("does not start the tour", async () => {
      // Given - a bare URL
      searchParamsValue = new URLSearchParams();

      // When - the trigger mounts
      render(<ProvidersOnboardingTrigger openWizard={vi.fn()} />);

      // Then - nothing is triggered
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
      expect(replaceMock).not.toHaveBeenCalled();
    });
  });

  describe("when the onboarding param does not match a known flow", () => {
    it("does not start the tour", async () => {
      // Given - an unknown flow id in the URL
      searchParamsValue = new URLSearchParams("onboarding=unknown-xyz");

      // When - the trigger mounts
      render(<ProvidersOnboardingTrigger openWizard={vi.fn()} />);

      // Then - nothing is triggered
      await waitFor(() => expect(startMock).not.toHaveBeenCalled());
      expect(replaceMock).not.toHaveBeenCalled();
    });
  });
});
