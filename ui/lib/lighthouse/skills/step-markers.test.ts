import { describe, expect, it } from "vitest";

import { consumeStepMarkers, stripStepMarkers } from "./step-markers";

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

  it("should release a suffix whose digits exceed the marker cap as text", () => {
    // Given: more digits than any valid marker carries — this can never
    // complete, so holding it back would swallow real text forever.
    const result = consumeStepMarkers("", "Result [[step:123456");

    // Then
    expect(result.text).toBe("Result [[step:123456");
    expect(result.carry).toBe("");
    expect(result.steps).toEqual([]);
  });

  it("should complete a marker at the digit cap split across chunks", () => {
    // Given
    const first = consumeStepMarkers("", "Text [[step:1234");
    expect(first.text).toBe("Text ");
    expect(first.carry).toBe("[[step:1234");

    // When
    const second = consumeStepMarkers(first.carry, "]]done");

    // Then
    expect(second.text).toBe("done");
    expect(second.steps).toEqual([1234]);
  });

  it("should hold a marker missing only its closing bracket", () => {
    const first = consumeStepMarkers("", "[[step:12]");
    expect(first).toEqual({ text: "", carry: "[[step:12]", steps: [] });

    const second = consumeStepMarkers(first.carry, "]");
    expect(second).toEqual({ text: "", carry: "", steps: [12] });
  });
});

describe("stripStepMarkers", () => {
  it("should remove inline markers from persisted assistant text", () => {
    expect(
      stripStepMarkers("[[step:1]] I'm gathering the focused finding."),
    ).toBe("I'm gathering the focused finding.");
  });

  it("should remove marker-only lines, including bulleted ones", () => {
    // Real-world model output: markers emitted as their own list items.
    const text = [
      "* [[step:1]]",
      "* Gathering the focused finding and affected resource context.",
      "* [[step:2]]",
      "* Enumerating identities with access.",
      "* [[step:3]] Mapping reachable services and resources.",
    ].join("\n");

    expect(stripStepMarkers(text)).toBe(
      [
        "* Gathering the focused finding and affected resource context.",
        "* Enumerating identities with access.",
        "* Mapping reachable services and resources.",
      ].join("\n"),
    );
  });

  it("should leave marker-free text untouched", () => {
    expect(stripStepMarkers("Plain **markdown** answer.")).toBe(
      "Plain **markdown** answer.",
    );
  });
});
