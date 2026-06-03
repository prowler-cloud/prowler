import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { addProviderTour } from "@/lib/tours/add-provider.tour";
import { buildStorageKey } from "@/lib/tours/store/local-storage-adapter";

import { OnboardingGate } from "../onboarding-gate";

const pushMock = vi.fn();

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock, replace: vi.fn() }),
}));

const addProviderStorageKey = buildStorageKey({
  id: addProviderTour.id,
  version: addProviderTour.version,
});

describe("OnboardingGate", () => {
  beforeEach(() => {
    window.localStorage.clear();
    pushMock.mockClear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when the user has no providers and no completion record", () => {
    it("shows the Welcome modal", async () => {
      // Given - a fresh browser with no providers
      render(<OnboardingGate hasProviders={false} />);

      // Then - the gate surfaces the Welcome modal for the first flow
      expect(
        await screen.findByRole("button", { name: /get started/i }),
      ).toBeInTheDocument();
    });
  });

  describe("when the user already has providers", () => {
    it("does not show the Welcome modal", async () => {
      // Given - a user with providers
      render(<OnboardingGate hasProviders={true} />);

      // Then - the modal is never displayed
      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("when a completion record already exists in this browser", () => {
    it("does not show the Welcome modal", async () => {
      // Given - a prior dismissal record for the first flow
      window.localStorage.setItem(
        addProviderStorageKey,
        JSON.stringify({
          tourId: addProviderTour.id,
          version: addProviderTour.version,
          state: "dismissed",
          completedAt: new Date().toISOString(),
        }),
      );

      render(<OnboardingGate hasProviders={false} />);

      // Then - the gate respects the record and stays silent
      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("when hasProviders is undefined (fail-open)", () => {
    it("does not show the Welcome modal", async () => {
      // Given - an ambiguous provider signal (transient / errored). The prop is
      // optional (`boolean | undefined`) so `undefined` is passed type-cleanly,
      // mirroring the tri-state the layout forwards on a failed provider fetch.
      render(<OnboardingGate hasProviders={undefined} />);

      // Then - the gate fails open and does not force onboarding
      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });

    it("can be mounted with the prop omitted entirely (fail-open)", async () => {
      // Given - the layout forwards `undefined` (omitted) when the provider
      // fetch failed; the gate must still fail open rather than force the modal.
      render(<OnboardingGate />);

      // Then - no modal
      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /get started/i }),
        ).not.toBeInTheDocument();
      });
    });
  });

  describe("when the user accepts the Welcome modal", () => {
    it("navigates to the flow route with the onboarding query param and writes no record", async () => {
      // Given - the modal is shown for a zero-provider user
      const user = userEvent.setup();
      render(<OnboardingGate hasProviders={false} />);
      const getStarted = await screen.findByRole("button", {
        name: /get started/i,
      });

      // When - the user accepts
      await user.click(getStarted);

      // Then - the gate hands off via the URL and persists nothing yet
      expect(pushMock).toHaveBeenCalledWith(
        "/providers?onboarding=add-provider",
      );
      expect(window.localStorage.getItem(addProviderStorageKey)).toBeNull();
    });
  });

  describe("when the user dismisses the Welcome modal", () => {
    it("writes a dismissed record and stops showing the modal", async () => {
      // Given - the modal is shown for a zero-provider user
      const user = userEvent.setup();
      render(<OnboardingGate hasProviders={false} />);
      const skip = await screen.findByRole("button", {
        name: /skip for now/i,
      });

      // When - the user skips
      await user.click(skip);

      // Then - a dismissal record is written and the modal closes
      await waitFor(() => {
        expect(
          screen.queryByRole("button", { name: /skip for now/i }),
        ).not.toBeInTheDocument();
      });
      const raw = window.localStorage.getItem(addProviderStorageKey);
      expect(raw).not.toBeNull();
      expect(JSON.parse(raw as string).state).toBe("dismissed");
    });
  });
});
