import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";

import { OnboardingCheckpointWatcher } from "../onboarding-checkpoint-watcher";

const pushMock = vi.fn();
const startSequenceMock = vi.fn();
const closeMock = vi.fn();

const CHECKPOINT_MARKER = "prowler.onboarding.checkpoint";

// Drives the store `open` flag the watcher subscribes to. Tests set this before
// render to simulate the checkpoint being requested open/closed.
let checkpointOpenState = false;

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: pushMock }),
}));

vi.mock("@/store/onboarding-sequence", () => ({
  useOnboardingSequenceStore: {
    getState: () => ({ startSequence: startSequenceMock }),
  },
}));

vi.mock("@/store/onboarding-checkpoint", () => ({
  CHECKPOINT_MARKER: "prowler.onboarding.checkpoint",
  // The watcher reads `open` via a selector hook and calls `close` on resolve.
  useOnboardingCheckpointStore: Object.assign(
    (selector: (state: { open: boolean }) => unknown) =>
      selector({ open: checkpointOpenState }),
    {
      getState: () => ({ close: closeMock }),
    },
  ),
}));

describe("OnboardingCheckpointWatcher", () => {
  beforeEach(() => {
    pushMock.mockClear();
    startSequenceMock.mockClear();
    closeMock.mockClear();
    checkpointOpenState = false;
    window.localStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("rendering", () => {
    it("renders the dialog when the store open flag is true", () => {
      // Given/When - the store requested the checkpoint open
      checkpointOpenState = true;
      render(<OnboardingCheckpointWatcher />);

      // Then - the dialog is shown
      expect(
        screen.getByText("Provider connected — keep exploring?"),
      ).toBeInTheDocument();
    });

    it("does not render the dialog when the store open flag is false", () => {
      // Given/When - the store has not requested the checkpoint
      checkpointOpenState = false;
      render(<OnboardingCheckpointWatcher />);

      // Then - nothing is shown
      expect(
        screen.queryByText("Provider connected — keep exploring?"),
      ).not.toBeInTheDocument();
    });
  });

  describe("when the user continues the tour", () => {
    it("marks handled, starts the sequence at the next flow, navigates, and closes the store", async () => {
      // Given - the dialog is open
      const user = userEvent.setup();
      checkpointOpenState = true;
      render(<OnboardingCheckpointWatcher />);
      await screen.findByText("Provider connected — keep exploring?");

      // When - the user continues
      await user.click(
        screen.getByRole("button", { name: /continue the tour/i }),
      );

      // Then - the marker is set, the sequence starts at the flow AFTER
      // add-provider, the watcher navigates, and it closes the store.
      const nextFlow = getFlowById("view-first-scan");
      expect(window.localStorage.getItem(CHECKPOINT_MARKER)).not.toBeNull();
      expect(closeMock).toHaveBeenCalledTimes(1);
      if (nextFlow) {
        expect(startSequenceMock).toHaveBeenCalledWith(nextFlow.id);
        expect(pushMock).toHaveBeenCalledWith(nextFlow.route);
      } else {
        // Registry still add-provider-only: guard gracefully.
        expect(startSequenceMock).not.toHaveBeenCalled();
        expect(pushMock).not.toHaveBeenCalled();
      }
    });
  });

  describe("when the user finishes here", () => {
    it("marks handled, starts no sequence, does not navigate, and closes the store", async () => {
      // Given - the dialog is open
      const user = userEvent.setup();
      checkpointOpenState = true;
      render(<OnboardingCheckpointWatcher />);
      await screen.findByText("Provider connected — keep exploring?");

      // When - the user finishes here
      await user.click(screen.getByRole("button", { name: /finish here/i }));

      // Then - the marker is set, no sequence starts, no navigation, store closed
      expect(window.localStorage.getItem(CHECKPOINT_MARKER)).not.toBeNull();
      expect(startSequenceMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
      await waitFor(() => expect(closeMock).toHaveBeenCalledTimes(1));
    });
  });
});
