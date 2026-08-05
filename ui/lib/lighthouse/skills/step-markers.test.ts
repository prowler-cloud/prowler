import { describe, expect, it } from "vitest";

import { consumeStepMarkers } from "./step-markers";

describe("consumeStepMarkers", () => {
  it("should pass plain text through untouched", () => {
    expect(consumeStepMarkers("", "Checking the trust policy.")).toEqual({
      text: "Checking the trust policy.",
      carry: "",
      steps: [],
    });
  });

  it("should strip complete markers and report their step numbers in order", () => {
    const result = consumeStepMarkers(
      "",
      "[[step:1]]Gathering context.[[step:2]]Enumerating identities.",
    );

    expect(result.steps).toEqual([1, 2]);
    expect(result.text).toBe("Gathering context.Enumerating identities.");
    expect(result.carry).toBe("");
  });

  it("should hold back a chunk suffix that may be the start of a marker", () => {
    const first = consumeStepMarkers("", "Exposure confirmed.\n[[st");

    expect(first).toEqual({
      text: "Exposure confirmed.\n",
      carry: "[[st",
      steps: [],
    });

    const second = consumeStepMarkers(first.carry, "ep:3]]\nChecking paths.");

    expect(second.steps).toEqual([3]);
    expect(second.text).toBe("\nChecking paths.");
    expect(second.carry).toBe("");
  });

  it("should release held text once it can no longer become a marker", () => {
    const first = consumeStepMarkers("", "policies[");
    expect(first).toEqual({ text: "policies", carry: "[", steps: [] });

    const second = consumeStepMarkers(first.carry, "0] applies");
    expect(second).toEqual({ text: "[0] applies", carry: "", steps: [] });
  });

  it("should hold a marker missing only its closing bracket", () => {
    const first = consumeStepMarkers("", "[[step:12]");
    expect(first).toEqual({ text: "", carry: "[[step:12]", steps: [] });

    const second = consumeStepMarkers(first.carry, "]");
    expect(second).toEqual({ text: "", carry: "", steps: [12] });
  });
});
