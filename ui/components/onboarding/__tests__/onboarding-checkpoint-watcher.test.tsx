import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";

import { OnboardingCheckpointWatcher } from "../onboarding-checkpoint-watcher";

const pushMock = vi.fn();
const startSequenceMock = vi.fn();

const CHECKPOINT_MARKER = "prowler.onboarding.checkpoint";

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/store/onboarding-sequence", () => ({
  useOnboardingSequenceStore: {
    getState: () => ({ startSequence: startSequenceMock }),
  },
}));

describe("OnboardingCheckpointWatcher", () => {
  beforeEach(() => {
    pushMock.mockClear();
    startSequenceMock.mockClear();
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("firing rules", () => {
    it("opens the dialog on a concrete false -> true flip", async () => {
      // Given - the watcher first observes a no-provider state from the prop
      const { rerender } = render(
        <OnboardingCheckpointWatcher hasProviders={false} />,
      );
      expect(
        screen.queryByText("Provider connected — keep exploring?"),
      ).not.toBeInTheDocument();

      // When - the layout re-computes hasProviders to true after first connect
      rerender(<OnboardingCheckpointWatcher hasProviders={true} />);

      // Then - the checkpoint dialog appears
      expect(
        await screen.findByText("Provider connected — keep exploring?"),
      ).toBeInTheDocument();
    });

    it("does not fire when hasProviders is true from the first render", () => {
      // Given/When - a user who already has providers: the layout passes
      // `true` from the FIRST render (prev=undefined, next=true). This is the
      // regression guard for the store-hydration false-fire bug.
      render(<OnboardingCheckpointWatcher hasProviders={true} />);

      // Then - the checkpoint must NOT fire on the initial read
      expect(
        screen.queryByText("Provider connected — keep exploring?"),
      ).not.toBeInTheDocument();
    });

    it("does not fire on a true -> true steady state", () => {
      // Given - the user already had providers on the first observed render
      const { rerender } = render(
        <OnboardingCheckpointWatcher hasProviders={true} />,
      );

      // When - providers stay present across a re-render
      rerender(<OnboardingCheckpointWatcher hasProviders={true} />);

      // Then - no checkpoint (no false -> true flip)
      expect(
        screen.queryByText("Provider connected — keep exploring?"),
      ).not.toBeInTheDocument();
    });

    it("does not fire when hasProviders is undefined (failed/ambiguous fetch)", () => {
      // Given/When - the layout could not determine provider state
      const { rerender } = render(
        <OnboardingCheckpointWatcher hasProviders={undefined} />,
      );
      rerender(<OnboardingCheckpointWatcher hasProviders={undefined} />);

      // Then - an unknown provider signal stays inert
      expect(
        screen.queryByText("Provider connected — keep exploring?"),
      ).not.toBeInTheDocument();
    });

    it("does not fire when the checkpoint was already handled", () => {
      // Given - the marker is already set from a previous session
      window.localStorage.setItem(CHECKPOINT_MARKER, "true");
      const { rerender } = render(
        <OnboardingCheckpointWatcher hasProviders={false} />,
      );

      // When - a false -> true flip happens
      rerender(<OnboardingCheckpointWatcher hasProviders={true} />);

      // Then - the marker suppresses the dialog
      expect(
        screen.queryByText("Provider connected — keep exploring?"),
      ).not.toBeInTheDocument();
    });
  });

  describe("when the user continues the tour", () => {
    it("marks handled, starts the sequence at the next flow, and navigates", async () => {
      // Given - the dialog is open after a first-connect flip
      const user = userEvent.setup();
      const { rerender } = render(
        <OnboardingCheckpointWatcher hasProviders={false} />,
      );
      rerender(<OnboardingCheckpointWatcher hasProviders={true} />);
      await screen.findByText("Provider connected — keep exploring?");

      // When - the user continues
      await user.click(
        screen.getByRole("button", { name: /continue the tour/i }),
      );

      // Then - the marker is set, the sequence starts at the flow AFTER
      // add-provider, and the watcher navigates to that flow's route.
      const nextFlow = getFlowById("view-first-scan");
      expect(window.localStorage.getItem(CHECKPOINT_MARKER)).not.toBeNull();
      if (nextFlow) {
        expect(startSequenceMock).toHaveBeenCalledWith(nextFlow.id);
        expect(pushMock).toHaveBeenCalledWith(nextFlow.route);
      } else {
        // Registry still add-provider-only (Slices 4-6 not landed): guard
        // gracefully — no crash, no sequence start, no navigation.
        expect(startSequenceMock).not.toHaveBeenCalled();
        expect(pushMock).not.toHaveBeenCalled();
      }

      // And - the dialog closes either way.
      await waitFor(() =>
        expect(
          screen.queryByText("Provider connected — keep exploring?"),
        ).not.toBeInTheDocument(),
      );
    });
  });

  describe("when the user finishes here", () => {
    it("marks handled and does not start a sequence or navigate", async () => {
      // Given - the dialog is open after a first-connect flip
      const user = userEvent.setup();
      const { rerender } = render(
        <OnboardingCheckpointWatcher hasProviders={false} />,
      );
      rerender(<OnboardingCheckpointWatcher hasProviders={true} />);
      await screen.findByText("Provider connected — keep exploring?");

      // When - the user finishes here
      await user.click(screen.getByRole("button", { name: /finish here/i }));

      // Then - the marker is set, no sequence starts, no navigation happens
      expect(window.localStorage.getItem(CHECKPOINT_MARKER)).not.toBeNull();
      expect(startSequenceMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
      await waitFor(() =>
        expect(
          screen.queryByText("Provider connected — keep exploring?"),
        ).not.toBeInTheDocument(),
      );
    });

    it("stays handled so the dialog never re-appears on a later flip", async () => {
      // Given - the user finished once, setting the marker
      const user = userEvent.setup();
      const { rerender } = render(
        <OnboardingCheckpointWatcher hasProviders={false} />,
      );
      rerender(<OnboardingCheckpointWatcher hasProviders={true} />);
      await screen.findByText("Provider connected — keep exploring?");
      await user.click(screen.getByRole("button", { name: /finish here/i }));
      await waitFor(() =>
        expect(
          screen.queryByText("Provider connected — keep exploring?"),
        ).not.toBeInTheDocument(),
      );

      // When - a fresh false -> true flip occurs later
      rerender(<OnboardingCheckpointWatcher hasProviders={false} />);
      rerender(<OnboardingCheckpointWatcher hasProviders={true} />);

      // Then - the marker keeps the dialog suppressed
      expect(
        screen.queryByText("Provider connected — keep exploring?"),
      ).not.toBeInTheDocument();
    });
  });
});
