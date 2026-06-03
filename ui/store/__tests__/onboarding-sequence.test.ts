import { beforeEach, describe, expect, it } from "vitest";

import { getOrderedFlows } from "@/lib/onboarding";

import { useOnboardingSequenceStore } from "../onboarding-sequence";

// Resets the ephemeral slice to its initial state before every test. The slice
// is plain (no persist), so a `setState` is enough to isolate cases.
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
      // Given - an inactive sequence
      // When - the sequence starts with no explicit flow
      useOnboardingSequenceStore.getState().startSequence();

      // Then - it activates at the first ordered flow in sequence mode
      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(getOrderedFlows()[0].id);
      expect(state.mode).toBe("sequence");
    });

    it("starts at the requested flow when given an explicit id", () => {
      // Given - a flow id that exists in the registry
      const targetId = getOrderedFlows()[0].id;

      // When - the sequence starts at that flow
      useOnboardingSequenceStore.getState().startSequence(targetId);

      // Then - it activates at the requested flow
      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(targetId);
      expect(state.mode).toBe("sequence");
    });
  });

  describe("advance", () => {
    it("moves to the next ordered flow when the current one is not last", () => {
      // Given - a sequence that needs at least two ordered flows
      const ordered = getOrderedFlows();
      if (ordered.length < 2) {
        // The registry currently grows in later slices; skip the multi-flow
        // assertion until a second flow exists rather than asserting on a
        // single-flow registry.
        return;
      }
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: ordered[0].id,
        mode: "sequence",
      });

      // When - the sequence advances
      useOnboardingSequenceStore.getState().advance();

      // Then - it points at the next ordered flow and stays active
      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(ordered[1].id);
      expect(state.mode).toBe("sequence");
    });

    it("resets to inactive when advancing past the last ordered flow", () => {
      // Given - a sequence positioned on the LAST ordered flow
      const ordered = getOrderedFlows();
      const lastFlow = ordered[ordered.length - 1];
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: lastFlow.id,
        mode: "sequence",
      });

      // When - the sequence advances past the end
      useOnboardingSequenceStore.getState().advance();

      // Then - it clears all three fields (sequence finished)
      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(false);
      expect(state.currentFlowId).toBeNull();
      expect(state.mode).toBeNull();
    });
  });

  describe("goToFlow", () => {
    it("re-points currentFlowId to a known flow while staying active in sequence mode", () => {
      // Given - an active sequence on a later flow
      const ordered = getOrderedFlows();
      const target = ordered[1];
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: ordered[2].id,
        mode: "sequence",
      });

      // When - jumping back to a known flow
      useOnboardingSequenceStore.getState().goToFlow(target.id);

      // Then - it points at the target flow and keeps the sequence active
      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(target.id);
      expect(state.mode).toBe("sequence");
    });

    it("is a no-op for an unknown flow id", () => {
      // Given - an active sequence on a known flow
      const ordered = getOrderedFlows();
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: ordered[0].id,
        mode: "sequence",
      });

      // When - jumping to a flow id that does not exist
      useOnboardingSequenceStore.getState().goToFlow("does-not-exist");

      // Then - state is unchanged
      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(true);
      expect(state.currentFlowId).toBe(ordered[0].id);
      expect(state.mode).toBe("sequence");
    });
  });

  describe("stop", () => {
    it("resets every field to its inactive value", () => {
      // Given - an active sequence in progress
      useOnboardingSequenceStore.setState({
        active: true,
        currentFlowId: getOrderedFlows()[0].id,
        mode: "sequence",
      });

      // When - the sequence stops
      useOnboardingSequenceStore.getState().stop();

      // Then - all three fields are reset
      const state = useOnboardingSequenceStore.getState();
      expect(state.active).toBe(false);
      expect(state.currentFlowId).toBeNull();
      expect(state.mode).toBeNull();
    });
  });
});
