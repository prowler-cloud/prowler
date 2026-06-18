import { beforeEach, describe, expect, it } from "vitest";

import { getOrderedFlows } from "@/lib/onboarding";

import { useOnboardingReplayStore } from "../onboarding-replay";

// Plain (no-persist) slice — setState is sufficient to isolate tests.
function resetStore(): void {
  useOnboardingReplayStore.setState({ flowId: null, token: 0 });
}

describe("useOnboardingReplayStore", () => {
  beforeEach(() => {
    resetStore();
  });

  describe("requestReplay", () => {
    it("sets the flow id and bumps the token for a known flow", () => {
      const target = getOrderedFlows()[0];

      useOnboardingReplayStore.getState().requestReplay(target.id);

      const state = useOnboardingReplayStore.getState();
      expect(state.flowId).toBe(target.id);
      expect(state.token).toBe(1);
    });

    it("bumps the token again when the same flow is requested twice", () => {
      const target = getOrderedFlows()[0];

      useOnboardingReplayStore.getState().requestReplay(target.id);
      useOnboardingReplayStore.getState().consume();
      useOnboardingReplayStore.getState().requestReplay(target.id);

      const state = useOnboardingReplayStore.getState();
      expect(state.flowId).toBe(target.id);
      // Monotonic token guarantees a fresh signal so the runner re-mounts.
      expect(state.token).toBe(2);
    });

    it("is a no-op for an unknown flow id", () => {
      useOnboardingReplayStore.getState().requestReplay("does-not-exist");

      const state = useOnboardingReplayStore.getState();
      expect(state.flowId).toBeNull();
      expect(state.token).toBe(0);
    });
  });

  describe("consume", () => {
    it("clears the flow id without resetting the token", () => {
      const target = getOrderedFlows()[0];
      useOnboardingReplayStore.getState().requestReplay(target.id);

      useOnboardingReplayStore.getState().consume();

      const state = useOnboardingReplayStore.getState();
      expect(state.flowId).toBeNull();
      expect(state.token).toBe(1);
    });
  });
});
