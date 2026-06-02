import { describe, expect, it } from "vitest";

import {
  mapCloseToSequenceAction,
  resolveTriggerRequest,
} from "../onboarding-trigger.logic";

describe("resolveTriggerRequest", () => {
  describe("replay (param) path", () => {
    it("requests a replay start when the param matches this flow", () => {
      // Given - the URL carries `?onboarding=<flowId>` for THIS route's flow
      // When - the trigger resolves the request
      const result = resolveTriggerRequest({
        param: "add-provider",
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      // Then - it starts in replay mode (single-flow, no sequence)
      expect(result).toEqual({ start: true, mode: "replay" });
    });

    it("takes precedence over the sequence when the param matches", () => {
      // Given - both the param and the active slice name THIS flow
      // When - the trigger resolves the request
      const result = resolveTriggerRequest({
        param: "add-provider",
        sliceActive: true,
        currentFlowId: "add-provider",
        flowId: "add-provider",
      });

      // Then - the documented precedence picks replay deterministically
      expect(result).toEqual({ start: true, mode: "replay" });
    });
  });

  describe("sequence (slice) path", () => {
    it("requests a sequence start when the active slice names this flow", () => {
      // Given - no param, but the active sequence points at THIS flow
      // When - the trigger resolves the request
      const result = resolveTriggerRequest({
        param: null,
        sliceActive: true,
        currentFlowId: "add-provider",
        flowId: "add-provider",
      });

      // Then - it starts in sequence mode
      expect(result).toEqual({ start: true, mode: "sequence" });
    });

    it("does not start when the active slice names a different flow", () => {
      // Given - the active sequence points at ANOTHER flow
      // When - the trigger resolves the request
      const result = resolveTriggerRequest({
        param: null,
        sliceActive: true,
        currentFlowId: "view-first-scan",
        flowId: "add-provider",
      });

      // Then - no start is requested for this route's flow
      expect(result).toBeNull();
    });

    it("does not start when the slice is inactive even if the id matches", () => {
      // Given - the slice names this flow but is inactive
      // When - the trigger resolves the request
      const result = resolveTriggerRequest({
        param: null,
        sliceActive: false,
        currentFlowId: "add-provider",
        flowId: "add-provider",
      });

      // Then - no start (an inactive slice never drives a start)
      expect(result).toBeNull();
    });
  });

  describe("no-match path", () => {
    it("returns null when the param targets a different flow and the slice is inactive", () => {
      // Given - a param for ANOTHER flow and an inactive slice
      // When - the trigger resolves the request
      const result = resolveTriggerRequest({
        param: "view-first-scan",
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      // Then - this route's flow has nothing to start
      expect(result).toBeNull();
    });

    it("returns null when neither the param nor the slice match", () => {
      // Given - no param and no active slice
      // When - the trigger resolves the request
      const result = resolveTriggerRequest({
        param: null,
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      // Then - null
      expect(result).toBeNull();
    });
  });
});

describe("mapCloseToSequenceAction", () => {
  it("advances the sequence when the tour completes", () => {
    // Given/When/Then - last-step completion drives the sequence forward
    expect(mapCloseToSequenceAction("completed")).toBe("advance");
  });

  it("stops the sequence when the tour is skipped", () => {
    // Given/When/Then - a mid-tour skip ends the sequence
    expect(mapCloseToSequenceAction("skipped")).toBe("stop");
  });

  it("stops the sequence when the tour is dismissed", () => {
    // Given/When/Then - an unmount/dismiss ends the sequence
    expect(mapCloseToSequenceAction("dismissed")).toBe("stop");
  });
});
