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
      render(
        <OnboardingCheckpointDialog
          open
          onContinue={vi.fn()}
          onFinish={vi.fn()}
        />,
      );

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

      await user.click(
        screen.getByRole("button", { name: /continue the tour/i }),
      );

      expect(onContinue).toHaveBeenCalledTimes(1);
      expect(onFinish).not.toHaveBeenCalled();
    });

    it("calls onFinish when the outline button is clicked", async () => {
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

      await user.click(screen.getByRole("button", { name: /finish here/i }));

      expect(onFinish).toHaveBeenCalledTimes(1);
      expect(onContinue).not.toHaveBeenCalled();
    });

    it("treats Escape (overlay/X dismiss) as finish", async () => {
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

      await user.keyboard("{Escape}");

      // Escape/overlay dismiss must route to onFinish, not onContinue.
      await waitFor(() => expect(onFinish).toHaveBeenCalledTimes(1));
      expect(onContinue).not.toHaveBeenCalled();
    });
  });

  describe("when closed", () => {
    it("renders nothing", () => {
      render(
        <OnboardingCheckpointDialog
          open={false}
          onContinue={vi.fn()}
          onFinish={vi.fn()}
        />,
      );

      expect(
        screen.queryByText("Provider added — keep exploring?"),
      ).not.toBeInTheDocument();
    });
  });
});
