import { beforeEach, describe, expect, it } from "vitest";

import {
  selectLighthouseContextItems,
  useLighthouseContextStore,
} from "./store";

describe("useLighthouseContextStore", () => {
  beforeEach(() => {
    useLighthouseContextStore.getState().resetContributions();
  });

  it("should expose only contributions for the current page scope", () => {
    // Given
    const { registerContribution } = useLighthouseContextStore.getState();
    registerContribution("findings-total", {
      kind: "finding",
      id: "findings-summary",
      source: "automatic",
      scopeKey: "findings:/findings",
      label: "Visible findings",
      findingId: "summary",
      total: 42,
    });
    registerContribution("resources-total", {
      kind: "resource",
      id: "resources-summary",
      source: "automatic",
      scopeKey: "resources:/resources",
      label: "Visible resources",
      resourceId: "summary",
      total: 12,
    });

    // When
    const items = selectLighthouseContextItems(
      useLighthouseContextStore.getState(),
      "resources:/resources",
    );

    // Then
    expect(items.map((item) => item.id)).toEqual(["resources-summary"]);
  });

  it("should replace a contribution when an interaction updates it", () => {
    // Given
    const { registerContribution } = useLighthouseContextStore.getState();
    registerContribution("selected-resource", {
      kind: "resource",
      id: "resource-1",
      source: "selection",
      scopeKey: "resources:/resources",
      label: "Selected resource",
      resourceId: "resource-1",
    });

    // When
    registerContribution("selected-resource", {
      kind: "resource",
      id: "resource-2",
      source: "selection",
      scopeKey: "resources:/resources",
      label: "Selected resource",
      resourceId: "resource-2",
    });

    // Then
    expect(
      selectLighthouseContextItems(
        useLighthouseContextStore.getState(),
        "resources:/resources",
      ).map((item) => item.id),
    ).toEqual(["resource-2"]);
  });
});
