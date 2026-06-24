import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { OnboardingWelcomeModal } from "../onboarding-welcome-modal";

describe("OnboardingWelcomeModal", () => {
  describe("when open is true", () => {
    it("renders the flow title and description", () => {
      render(
        <OnboardingWelcomeModal
          open
          flowTitle="Add your first provider"
          flowDescription="Connect a cloud account so Prowler has something to scan."
          onAccept={vi.fn()}
          onDismiss={vi.fn()}
        />,
      );

      expect(screen.getByText("Add your first provider")).toBeInTheDocument();
      expect(
        screen.getByText(
          "Connect a cloud account so Prowler has something to scan.",
        ),
      ).toBeInTheDocument();
    });

    it("calls onAccept when the primary action is clicked", async () => {
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

      await user.click(screen.getByRole("button", { name: /get started/i }));

      expect(onAccept).toHaveBeenCalledTimes(1);
      expect(onDismiss).not.toHaveBeenCalled();
    });

    it("calls onDismiss when the skip action is clicked", async () => {
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

      await user.click(screen.getByRole("button", { name: /skip for now/i }));

      expect(onDismiss).toHaveBeenCalledTimes(1);
      expect(onAccept).not.toHaveBeenCalled();
    });
  });

  describe("when open is false", () => {
    it("does not render the modal content", () => {
      render(
        <OnboardingWelcomeModal
          open={false}
          flowTitle="Add your first provider"
          onAccept={vi.fn()}
          onDismiss={vi.fn()}
        />,
      );

      expect(
        screen.queryByRole("button", { name: /get started/i }),
      ).not.toBeInTheDocument();
    });
  });
});
