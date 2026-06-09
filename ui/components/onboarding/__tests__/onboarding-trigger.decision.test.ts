import { describe, expect, it } from "vitest";

import {
  mapCloseToSequenceAction,
  resolveTriggerRequest,
} from "../onboarding-trigger.logic";

describe("resolveTriggerRequest", () => {
  describe("replay (param) path", () => {
    it("requests a replay start when the param matches this flow", () => {
      const result = resolveTriggerRequest({
        param: "add-provider",
        replayRequestFlowId: null,
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      expect(result).toEqual({ start: true, mode: "replay" });
    });

    it("takes precedence over the sequence when the param matches", () => {
      const result = resolveTriggerRequest({
        param: "add-provider",
        replayRequestFlowId: null,
        sliceActive: true,
        currentFlowId: "add-provider",
        flowId: "add-provider",
      });

      // Param takes precedence over sequence when both match.
      expect(result).toEqual({ start: true, mode: "replay" });
    });

    it("takes precedence over an in-memory replay request", () => {
      const result = resolveTriggerRequest({
        param: "add-provider",
        replayRequestFlowId: "add-provider",
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      // Both resolve to replay; the param branch wins but the mode is identical.
      expect(result).toEqual({ start: true, mode: "replay" });
    });
  });

  describe("replay (in-memory request) path", () => {
    it("requests a replay start when the store names this flow", () => {
      const result = resolveTriggerRequest({
        param: null,
        replayRequestFlowId: "add-provider",
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      expect(result).toEqual({ start: true, mode: "replay" });
    });

    it("takes precedence over the sequence when the store names this flow", () => {
      const result = resolveTriggerRequest({
        param: null,
        replayRequestFlowId: "add-provider",
        sliceActive: true,
        currentFlowId: "add-provider",
        flowId: "add-provider",
      });

      expect(result).toEqual({ start: true, mode: "replay" });
    });

    it("does not start when the store names a different flow", () => {
      const result = resolveTriggerRequest({
        param: null,
        replayRequestFlowId: "view-first-scan",
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      expect(result).toBeNull();
    });
  });

  describe("sequence (slice) path", () => {
    it("requests a sequence start when the active slice names this flow", () => {
      const result = resolveTriggerRequest({
        param: null,
        replayRequestFlowId: null,
        sliceActive: true,
        currentFlowId: "add-provider",
        flowId: "add-provider",
      });

      expect(result).toEqual({ start: true, mode: "sequence" });
    });

    it("does not start when the active slice names a different flow", () => {
      const result = resolveTriggerRequest({
        param: null,
        replayRequestFlowId: null,
        sliceActive: true,
        currentFlowId: "view-first-scan",
        flowId: "add-provider",
      });

      expect(result).toBeNull();
    });

    it("does not start when the slice is inactive even if the id matches", () => {
      const result = resolveTriggerRequest({
        param: null,
        replayRequestFlowId: null,
        sliceActive: false,
        currentFlowId: "add-provider",
        flowId: "add-provider",
      });

      expect(result).toBeNull();
    });
  });

  describe("no-match path", () => {
    it("returns null when the param targets a different flow and the slice is inactive", () => {
      const result = resolveTriggerRequest({
        param: "view-first-scan",
        replayRequestFlowId: null,
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      expect(result).toBeNull();
    });

    it("returns null when neither the param, the store, nor the slice match", () => {
      const result = resolveTriggerRequest({
        param: null,
        replayRequestFlowId: null,
        sliceActive: false,
        currentFlowId: null,
        flowId: "add-provider",
      });

      expect(result).toBeNull();
    });
  });
});

describe("mapCloseToSequenceAction", () => {
  it("advances the sequence when the tour completes", () => {
    expect(mapCloseToSequenceAction("completed")).toBe("advance");
  });

  it("stops the sequence when the tour is skipped", () => {
    expect(mapCloseToSequenceAction("skipped")).toBe("stop");
  });

  it("stops the sequence when the tour is dismissed", () => {
    expect(mapCloseToSequenceAction("dismissed")).toBe("stop");
  });
});
