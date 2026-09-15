import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { OnboardingProfileModal } from "../onboarding-profile-modal";

describe("OnboardingProfileModal", () => {
  it("asks the three closed questions and keeps Continue disabled until all are answered", async () => {
    // Given
    const user = userEvent.setup();
    const onSubmit = vi.fn();
    render(
      <OnboardingProfileModal open onSubmit={onSubmit} onSkip={vi.fn()} />,
    );
    const submit = screen.getByRole("button", { name: "Continue" });
    expect(submit).toBeDisabled();

    // When
    await user.click(screen.getByRole("radio", { name: "11-50" }));
    await user.click(screen.getByRole("radio", { name: "2-5" }));
    expect(submit).toBeDisabled();
    await user.click(screen.getByRole("radio", { name: "Security" }));
    await user.click(submit);

    // Then
    expect(onSubmit).toHaveBeenCalledWith({
      declared_cloud_accounts: "11-50",
      declared_team_size: "2-5",
      declared_role: "security",
    });
  });

  it("reports a skip from the secondary action and from closing the dialog", async () => {
    // Given
    const user = userEvent.setup();
    const onSkip = vi.fn();
    render(<OnboardingProfileModal open onSubmit={vi.fn()} onSkip={onSkip} />);

    // When
    await user.click(screen.getByRole("button", { name: "Skip" }));
    await user.keyboard("{Escape}");

    // Then
    expect(onSkip).toHaveBeenCalledTimes(2);
  });

  it("locks every control while a submission is in flight", async () => {
    // Given
    const user = userEvent.setup();
    const onSkip = vi.fn();
    render(
      <OnboardingProfileModal
        open
        isSubmitting
        onSubmit={vi.fn()}
        onSkip={onSkip}
      />,
    );

    // Then
    expect(screen.getByRole("button", { name: "Saving..." })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Skip" })).toBeDisabled();
    expect(screen.getByRole("radio", { name: "Security" })).toBeDisabled();

    // When — closing must not count as a skip mid-flight.
    await user.keyboard("{Escape}");

    // Then
    expect(onSkip).not.toHaveBeenCalled();
  });
});
