import { beforeEach, describe, expect, it } from "vitest";

import { useGraphStore } from "./use-graph-state";

describe("useGraphStore", () => {
  beforeEach(() => {
    useGraphStore.getState().reset();
  });

  it("keeps only one expanded findings resource open at a time", () => {
    // Given
    const store = useGraphStore.getState();

    // When
    store.toggleExpandedResource("resource-a");
    useGraphStore.getState().toggleExpandedResource("resource-b");

    // Then
    expect(Array.from(useGraphStore.getState().expandedResources)).toEqual([
      "resource-b",
    ]);
  });

  it("closes the expanded findings resource when toggled again", () => {
    // Given
    const store = useGraphStore.getState();

    // When
    store.toggleExpandedResource("resource-a");
    useGraphStore.getState().toggleExpandedResource("resource-a");

    // Then
    expect(useGraphStore.getState().expandedResources.size).toBe(0);
  });
});
