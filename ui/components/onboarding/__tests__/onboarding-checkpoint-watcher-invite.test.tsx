import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { onboardingInviteMarkerKey } from "@/lib/onboarding/invite-marker";

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

const TENANT_ID = "3f6c2f1e-7b0a-4d5c-9a21-0c9f4f2a7b10";
const OTHER_TENANT_ID = "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";
const MARKER_KEY = onboardingInviteMarkerKey(TENANT_ID) as string;

const CHECKPOINT_TITLE = "Provider added — keep exploring?";

describe("OnboardingCheckpointWatcher invite step", () => {
  beforeEach(() => {
    window.localStorage.clear();
    checkpointOpenState = true;
  });

  it("offers the invite step before the checkpoint dialog and keeps the store open", async () => {
    // Given
    const user = userEvent.setup();
    render(<OnboardingCheckpointWatcher tenantId={TENANT_ID} />);
    // The step is loaded on demand, so it arrives a tick after render.
    expect(
      await screen.findByRole("button", { name: "Resolve invite step" }),
    ).toBeInTheDocument();
    expect(screen.queryByText(CHECKPOINT_TITLE)).not.toBeInTheDocument();

    // When
    await user.click(
      screen.getByRole("button", { name: "Resolve invite step" }),
    );

    // Then
    expect(await screen.findByText(CHECKPOINT_TITLE)).toBeInTheDocument();
    expect(window.localStorage.getItem(MARKER_KEY)).toBe("true");
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
    window.localStorage.setItem(MARKER_KEY, "true");

    // When
    render(<OnboardingCheckpointWatcher tenantId={TENANT_ID} />);

    // Then
    expect(screen.getByText(CHECKPOINT_TITLE)).toBeInTheDocument();
  });

  it("renders nothing for the step while the checkpoint is not requested", () => {
    // Given
    checkpointOpenState = false;

    // When
    render(<OnboardingCheckpointWatcher tenantId={TENANT_ID} />);

    // Then
    expect(
      screen.queryByRole("button", { name: "Resolve invite step" }),
    ).not.toBeInTheDocument();
    expect(screen.queryByText(CHECKPOINT_TITLE)).not.toBeInTheDocument();
  });

  it("offers the step again to another tenant of the same browser", async () => {
    // Given — this browser already saw it for one tenant.
    window.localStorage.setItem(MARKER_KEY, "true");

    // When
    render(<OnboardingCheckpointWatcher tenantId={OTHER_TENANT_ID} />);

    // Then
    expect(
      await screen.findByRole("button", { name: "Resolve invite step" }),
    ).toBeInTheDocument();
  });

  it("does not offer the step without a usable tenant", () => {
    // When
    render(<OnboardingCheckpointWatcher tenantId={null} />);

    // Then
    expect(screen.getByText(CHECKPOINT_TITLE)).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Resolve invite step" }),
    ).not.toBeInTheDocument();
  });
});
