import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OnboardingCheckpointDialog } from "../onboarding-checkpoint-dialog";

describe("OnboardingCheckpointDialog", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  describe("when open", () => {
    it("shows the checkpoint title and both choices", () => {
      // Given - the checkpoint dialog is open
      render(
        <OnboardingCheckpointDialog
          open
          onContinue={vi.fn()}
          onFinish={vi.fn()}
        />,
      );

      // Then - the user sees the prompt and both actions
      expect(
        screen.getByText("Provider added — keep exploring?"),
      ).toBeInTheDocument();
      expect(
        screen.getByText(/Your first provider is added\./),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /continue the tour/i }),
      ).toBeInTheDocument();
      expect(
        screen.getByRole("button", { name: /finish here/i }),
      ).toBeInTheDocument();
    });

    it("calls onContinue when the primary button is clicked", async () => {
      // Given - an open dialog with distinct callbacks
      const user = userEvent.setup();
      const onContinue = vi.fn();
      const onFinish = vi.fn();
      render(
        <OnboardingCheckpointDialog
          open
          onContinue={onContinue}
          onFinish={onFinish}
        />,
      );

      // When - the user chooses to continue the tour
      await user.click(
        screen.getByRole("button", { name: /continue the tour/i }),
      );

      // Then - only onContinue fires
      expect(onContinue).toHaveBeenCalledTimes(1);
      expect(onFinish).not.toHaveBeenCalled();
    });

    it("calls onFinish when the ghost button is clicked", async () => {
      // Given - an open dialog with distinct callbacks
      const user = userEvent.setup();
      const onContinue = vi.fn();
      const onFinish = vi.fn();
      render(
        <OnboardingCheckpointDialog
          open
          onContinue={onContinue}
          onFinish={onFinish}
        />,
      );

      // When - the user chooses to finish here
      await user.click(screen.getByRole("button", { name: /finish here/i }));

      // Then - only onFinish fires
      expect(onFinish).toHaveBeenCalledTimes(1);
      expect(onContinue).not.toHaveBeenCalled();
    });

    it("treats Escape (overlay/X dismiss) as finish", async () => {
      // Given - an open dialog
      const user = userEvent.setup();
      const onContinue = vi.fn();
      const onFinish = vi.fn();
      render(
        <OnboardingCheckpointDialog
          open
          onContinue={onContinue}
          onFinish={onFinish}
        />,
      );

      // When - the user dismisses via Escape (same path as overlay/X)
      await user.keyboard("{Escape}");

      // Then - dismissal is treated as finishing, never continuing
      await waitFor(() => expect(onFinish).toHaveBeenCalledTimes(1));
      expect(onContinue).not.toHaveBeenCalled();
    });
  });

  describe("when closed", () => {
    it("renders nothing", () => {
      // Given/When - the dialog is closed
      render(
        <OnboardingCheckpointDialog
          open={false}
          onContinue={vi.fn()}
          onFinish={vi.fn()}
        />,
      );

      // Then - the prompt is not in the document
      expect(
        screen.queryByText("Provider added — keep exploring?"),
      ).not.toBeInTheDocument();
    });
  });
});
