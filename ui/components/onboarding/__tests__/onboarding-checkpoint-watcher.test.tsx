import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { getFlowById } from "@/lib/onboarding";

import { OnboardingCheckpointWatcher } from "../onboarding-checkpoint-watcher";

const pushMock = vi.fn();
const startSequenceMock = vi.fn();
const closeMock = vi.fn();

const CHECKPOINT_MARKER = "prowler.onboarding.checkpoint";

// Tests set this before render to control the store `open` flag the watcher subscribes to.
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
      checkpointOpenState = true;
      render(<OnboardingCheckpointWatcher />);

      expect(
        screen.getByText("Provider added — keep exploring?"),
      ).toBeInTheDocument();
    });

    it("does not render the dialog when the store open flag is false", () => {
      checkpointOpenState = false;
      render(<OnboardingCheckpointWatcher />);

      expect(
        screen.queryByText("Provider added — keep exploring?"),
      ).not.toBeInTheDocument();
    });
  });

  describe("when the user continues the tour", () => {
    it("marks handled, starts the sequence at the next flow, navigates, and closes the store", async () => {
      const user = userEvent.setup();
      checkpointOpenState = true;
      render(<OnboardingCheckpointWatcher />);
      await screen.findByText("Provider added — keep exploring?");

      await user.click(
        screen.getByRole("button", { name: /continue the tour/i }),
      );

      const nextFlow = getFlowById("view-first-scan");
      expect(window.localStorage.getItem(CHECKPOINT_MARKER)).not.toBeNull();
      expect(closeMock).toHaveBeenCalledTimes(1);
      if (nextFlow) {
        expect(startSequenceMock).toHaveBeenCalledWith(nextFlow.id);
        expect(pushMock).toHaveBeenCalledWith(nextFlow.route);
      } else {
        // Guard: registry is still add-provider-only.
        expect(startSequenceMock).not.toHaveBeenCalled();
        expect(pushMock).not.toHaveBeenCalled();
      }
    });
  });

  describe("when the user finishes here", () => {
    it("marks handled, starts no sequence, does not navigate, and closes the store", async () => {
      const user = userEvent.setup();
      checkpointOpenState = true;
      render(<OnboardingCheckpointWatcher />);
      await screen.findByText("Provider added — keep exploring?");

      await user.click(screen.getByRole("button", { name: /finish here/i }));

      expect(window.localStorage.getItem(CHECKPOINT_MARKER)).not.toBeNull();
      expect(startSequenceMock).not.toHaveBeenCalled();
      expect(pushMock).not.toHaveBeenCalled();
      await waitFor(() => expect(closeMock).toHaveBeenCalledTimes(1));
    });
  });
});
