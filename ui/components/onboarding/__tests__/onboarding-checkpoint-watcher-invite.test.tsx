import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ONBOARDING_INVITE_MARKER } from "@/lib/onboarding/invite-marker";

import { OnboardingCheckpointWatcher } from "../onboarding-checkpoint-watcher";

// Tests set this before render to control the store `open` flag.
let checkpointOpenState = false;

vi.mock("next/navigation", () => ({
  useRouter: () => ({ push: vi.fn() }),
}));

vi.mock("@/store/onboarding-sequence", () => ({
  useOnboardingSequenceStore: {
    getState: () => ({ startSequence: vi.fn() }),
  },
}));

vi.mock("@/store/onboarding-checkpoint", () => ({
  CHECKPOINT_MARKER: "prowler.onboarding.checkpoint",
  useOnboardingCheckpointStore: Object.assign(
    (selector: (state: { open: boolean }) => unknown) =>
      selector({ open: checkpointOpenState }),
    {
      getState: () => ({ close: vi.fn() }),
    },
  ),
}));

vi.mock("../onboarding-invite-step", () => ({
  OnboardingInviteStep: ({ onDone }: { onDone: () => void }) => (
    <button type="button" onClick={onDone}>
      Resolve invite step
    </button>
  ),
}));

const CHECKPOINT_TITLE = "Provider added — keep exploring?";

describe("OnboardingCheckpointWatcher invite step", () => {
  beforeEach(() => {
    window.localStorage.clear();
    checkpointOpenState = true;
  });

  it("offers the invite step before the checkpoint dialog and keeps the store open", async () => {
    // Given
    const user = userEvent.setup();
    render(<OnboardingCheckpointWatcher showInviteStep />);
    expect(
      screen.getByRole("button", { name: "Resolve invite step" }),
    ).toBeInTheDocument();
    expect(screen.queryByText(CHECKPOINT_TITLE)).not.toBeInTheDocument();

    // When
    await user.click(
      screen.getByRole("button", { name: "Resolve invite step" }),
    );

    // Then
    expect(await screen.findByText(CHECKPOINT_TITLE)).toBeInTheDocument();
    expect(window.localStorage.getItem(ONBOARDING_INVITE_MARKER)).toBe("true");
  });

  it("is off unless a deployment opts in", () => {
    // When
    render(<OnboardingCheckpointWatcher />);

    // Then
    expect(screen.getByText(CHECKPOINT_TITLE)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Resolve invite step" }),
    ).not.toBeInTheDocument();
  });

  it("does not offer the step again once this browser saw it", () => {
    // Given
    window.localStorage.setItem(ONBOARDING_INVITE_MARKER, "true");

    // When
    render(<OnboardingCheckpointWatcher showInviteStep />);

    // Then
    expect(screen.getByText(CHECKPOINT_TITLE)).toBeInTheDocument();
  });

  it("renders nothing for the step while the checkpoint is not requested", () => {
    // Given
    checkpointOpenState = false;

    // When
    render(<OnboardingCheckpointWatcher showInviteStep />);

    // Then
    expect(
      screen.queryByRole("button", { name: "Resolve invite step" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(CHECKPOINT_TITLE)).not.toBeInTheDocument();
  });
});
