import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { useOnboardingCheckpointStore } from "../onboarding-checkpoint";

const CHECKPOINT_MARKER = "prowler.onboarding.checkpoint";

describe("useOnboardingCheckpointStore", () => {
  beforeEach(() => {
    window.localStorage.clear();
    // Reset to a clean, disarmed/closed baseline between tests.
    useOnboardingCheckpointStore.setState({ armed: false, open: false });
  });

  afterEach(() => {
    window.localStorage.clear();
  });

  it("starts disarmed and closed", () => {
    const state = useOnboardingCheckpointStore.getState();
    expect(state.armed).toBe(false);
    expect(state.open).toBe(false);
  });

  it("arm() sets armed without opening", () => {
    useOnboardingCheckpointStore.getState().arm();

    const state = useOnboardingCheckpointStore.getState();
    expect(state.armed).toBe(true);
    expect(state.open).toBe(false);
  });

  it("requestOpenOnWizardClose opens only when armed, a provider connected, and not handled", () => {
    useOnboardingCheckpointStore.getState().arm();

    useOnboardingCheckpointStore
      .getState()
      .requestOpenOnWizardClose({ providerConnected: true });

    expect(useOnboardingCheckpointStore.getState().open).toBe(true);
  });

  it("does NOT open when not armed even if a provider connected", () => {
    // Given - the user is an established user who never went through onboarding
    // (the gate never armed the checkpoint), then adds another provider.
    useOnboardingCheckpointStore
      .getState()
      .requestOpenOnWizardClose({ providerConnected: true });

    expect(useOnboardingCheckpointStore.getState().open).toBe(false);
  });

  it("does NOT open when armed but no provider connected (wizard closed empty)", () => {
    useOnboardingCheckpointStore.getState().arm();

    useOnboardingCheckpointStore
      .getState()
      .requestOpenOnWizardClose({ providerConnected: false });

    expect(useOnboardingCheckpointStore.getState().open).toBe(false);
  });

  it("does NOT open when the checkpoint was already handled in this browser", () => {
    window.localStorage.setItem(CHECKPOINT_MARKER, "true");
    useOnboardingCheckpointStore.getState().arm();

    useOnboardingCheckpointStore
      .getState()
      .requestOpenOnWizardClose({ providerConnected: true });

    expect(useOnboardingCheckpointStore.getState().open).toBe(false);
  });

  it("close() resets open and disarms", () => {
    useOnboardingCheckpointStore.getState().arm();
    useOnboardingCheckpointStore
      .getState()
      .requestOpenOnWizardClose({ providerConnected: true });
    expect(useOnboardingCheckpointStore.getState().open).toBe(true);

    useOnboardingCheckpointStore.getState().close();

    const state = useOnboardingCheckpointStore.getState();
    expect(state.open).toBe(false);
    expect(state.armed).toBe(false);
  });
});
