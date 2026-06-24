import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { addProviderTour } from "@/lib/tours/add-provider.tour";
import { localStorageAdapter } from "@/lib/tours/store/local-storage-adapter";

import { OnboardingGate } from "../onboarding-gate";

const pushMock = vi.fn();
const armMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, replace: vi.fn() }),
}));

vi.mock("@/store/onboarding-checkpoint", () => ({
  useOnboardingCheckpointStore: {
    getState: () => ({ arm: armMock }),
  },
}));

const addProviderTourId = {
  id: addProviderTour.id,
  version: addProviderTour.version,
};

describe("OnboardingGate", () => {
  beforeEach(() => {
    window.localStorage.clear();
    pushMock.mockClear();
    armMock.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the user has no providers and no completion record", () => {
    it("shows the Welcome modal", async () => {
      render(<OnboardingGate hasProviders={false} />);

      expect(
        await screen.findByRole("button", { name: /get started/i }),
      ).toBeInTheDocument();
    });
  });

  describe("when the user already has providers", () => {
    it("does not show the Welcome modal", async () => {
      render(<OnboardingGate hasProviders={true} />);

      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("when a completion record already exists in this browser", () => {
    it("does not show the Welcome modal", async () => {
      localStorageAdapter.set(addProviderTourId, {
        tourId: addProviderTour.id,
        version: addProviderTour.version,
        state: "dismissed",
        completedAt: new Date().toISOString(),
      });

      render(<OnboardingGate hasProviders={false} />);

      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("when the gate flow is dismissed but later sequence flows are incomplete", () => {
    it("does not show the Welcome modal for a later flow", async () => {
      // Later flows are only reachable via the checkpoint/sequence, never the gate.
      localStorageAdapter.set(addProviderTourId, {
        tourId: addProviderTour.id,
        version: addProviderTour.version,
        state: "dismissed",
        completedAt: new Date().toISOString(),
      });

      render(<OnboardingGate hasProviders={false} />);

      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("when hasProviders is undefined (fail-open)", () => {
    it("does not show the Welcome modal", async () => {
      // `undefined` mirrors the tri-state layout forwards on a failed provider fetch.
      render(<OnboardingGate hasProviders={undefined} />);

      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });

    it("can be mounted with the prop omitted entirely (fail-open)", async () => {
      render(<OnboardingGate />);

      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("when the user accepts the Welcome modal", () => {
    it("navigates to the flow route with the onboarding query param and writes no record", async () => {
      const user = userEvent.setup();
      render(<OnboardingGate hasProviders={false} />);
      const getStarted = await screen.findByRole("button", {
        name: /get started/i,
      });

      await user.click(getStarted);

      expect(pushMock).toHaveBeenCalledWith(
        "/providers?onboarding=add-provider",
      );
      expect(localStorageAdapter.get(addProviderTourId)).toBeNull();
    });

    it("arms the onboarding checkpoint", async () => {
      const user = userEvent.setup();
      render(<OnboardingGate hasProviders={false} />);
      const getStarted = await screen.findByRole("button", {
        name: /get started/i,
      });

      await user.click(getStarted);

      expect(armMock).toHaveBeenCalledTimes(1);
    });
  });

  describe("when the user dismisses the Welcome modal", () => {
    it("writes a dismissed record and stops showing the modal", async () => {
      const user = userEvent.setup();
      render(<OnboardingGate hasProviders={false} />);
      const skip = await screen.findByRole("button", {
        name: /skip for now/i,
      });

      await user.click(skip);

      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /skip for now/i }),
        ).not.toBeInTheDocument();
      });
      const record = localStorageAdapter.get(addProviderTourId);
      expect(record).not.toBeNull();
      expect(record?.state).toBe("dismissed");
    });

    it("does NOT arm the onboarding checkpoint", async () => {
      const user = userEvent.setup();
      render(<OnboardingGate hasProviders={false} />);
      const skip = await screen.findByRole("button", {
        name: /skip for now/i,
      });

      await user.click(skip);

      // Skipping must never arm the checkpoint (user opted out).
      expect(armMock).not.toHaveBeenCalled();
    });
  });
});
