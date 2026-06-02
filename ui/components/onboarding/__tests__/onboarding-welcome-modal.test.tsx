import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { OnboardingWelcomeModal } from "../onboarding-welcome-modal";

describe("OnboardingWelcomeModal", () => {
  describe("when open is true", () => {
    it("renders the flow title and description", () => {
      // Given - an open modal with a flow's copy
      render(
        <OnboardingWelcomeModal
          open
          flowTitle="Add your first provider"
          flowDescription="Connect a cloud account so Prowler has something to scan."
          onAccept={vi.fn()}
          onDismiss={vi.fn()}
        />,
      );

      // Then - the modal surfaces the flow copy
      expect(screen.getByText("Add your first provider")).toBeInTheDocument();
      expect(
        screen.getByText(
          "Connect a cloud account so Prowler has something to scan.",
        ),
      ).toBeInTheDocument();
    });

    it("calls onAccept when the primary action is clicked", async () => {
      // Given - an open modal
      const user = userEvent.setup();
      const onAccept = vi.fn();
      const onDismiss = vi.fn();
      render(
        <OnboardingWelcomeModal
          open
          flowTitle="Add your first provider"
          onAccept={onAccept}
          onDismiss={onDismiss}
        />,
      );

      // When - the user clicks the primary CTA
      await user.click(screen.getByRole("button", { name: /get started/i }));

      // Then - only onAccept fires
      expect(onAccept).toHaveBeenCalledTimes(1);
      expect(onDismiss).not.toHaveBeenCalled();
    });

    it("calls onDismiss when the skip action is clicked", async () => {
      // Given - an open modal
      const user = userEvent.setup();
      const onAccept = vi.fn();
      const onDismiss = vi.fn();
      render(
        <OnboardingWelcomeModal
          open
          flowTitle="Add your first provider"
          onAccept={onAccept}
          onDismiss={onDismiss}
        />,
      );

      // When - the user clicks the secondary skip action
      await user.click(screen.getByRole("button", { name: /skip for now/i }));

      // Then - only onDismiss fires
      expect(onDismiss).toHaveBeenCalledTimes(1);
      expect(onAccept).not.toHaveBeenCalled();
    });
  });

  describe("when open is false", () => {
    it("does not render the modal content", () => {
      // Given - a closed modal
      render(
        <OnboardingWelcomeModal
          open={false}
          flowTitle="Add your first provider"
          onAccept={vi.fn()}
          onDismiss={vi.fn()}
        />,
      );

      // Then - the primary CTA is not in the document
      expect(
        screen.queryByRole("button", { name: /get started/i }),
      ).not.toBeInTheDocument();
    });
  });
});
