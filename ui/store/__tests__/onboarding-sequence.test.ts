import { beforeEach, describe, expect, it } from "vitest";

import { getOrderedFlows } from "@/lib/onboarding";

import { useOnboardingSequenceStore } from "../onboarding-sequence";

// Plain (no-persist) slice — setState is sufficient to isolate tests.
function resetStore(): void {
  useOnboardingSequenceStore.setState({
    active: false,
    currentFlowId: null,
    mode: null,
  });
}

describe("useOnboardingSequenceStore", () => {
  beforeEach(() => {
    resetStore();
  });

  describe("startSequence", () => {
    it("starts at the first ordered flow when called with no argument", () => {
      useOnboardingSequenceStore.getState().startSequence();

      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(getOrderedFlows()[0].id);
      expect(state.mode).toBe("sequence");
    });

    it("starts at the requested flow when given an explicit id", () => {
      const targetId = getOrderedFlows()[0].id;
      useOnboardingSequenceStore.getState().startSequence(targetId);

      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(targetId);
      expect(state.mode).toBe("sequence");
    });
  });

  describe("advance", () => {
    it("moves to the next ordered flow when the current one is not last", () => {
      const ordered = getOrderedFlows();
      if (ordered.length < 2) {
        // Skip until the registry has at least two flows.
        return;
      }
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: ordered[0].id,
        mode: "sequence",
      });

      useOnboardingSequenceStore.getState().advance();

      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(ordered[1].id);
      expect(state.mode).toBe("sequence");
    });

    it("resets to inactive when advancing past the last ordered flow", () => {
      const ordered = getOrderedFlows();
      const lastFlow = ordered[ordered.length - 1];
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: lastFlow.id,
        mode: "sequence",
      });

      useOnboardingSequenceStore.getState().advance();

      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(false);
      expect(state.currentFlowId).toBeNull();
      expect(state.mode).toBeNull();
    });
  });

  describe("goToFlow", () => {
    it("re-points currentFlowId to a known flow while staying active in sequence mode", () => {
      const ordered = getOrderedFlows();
      const target = ordered[1];
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: ordered[2].id,
        mode: "sequence",
      });

      useOnboardingSequenceStore.getState().goToFlow(target.id);

      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(target.id);
      expect(state.mode).toBe("sequence");
    });

    it("is a no-op for an unknown flow id", () => {
      const ordered = getOrderedFlows();
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: ordered[0].id,
        mode: "sequence",
      });

      useOnboardingSequenceStore.getState().goToFlow("does-not-exist");

      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(ordered[0].id);
      expect(state.mode).toBe("sequence");
    });
  });

  describe("stop", () => {
    it("resets every field to its inactive value", () => {
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: getOrderedFlows()[0].id,
        mode: "sequence",
      });

      useOnboardingSequenceStore.getState().stop();

      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(false);
      expect(state.currentFlowId).toBeNull();
      expect(state.mode).toBeNull();
    });
  });
});
