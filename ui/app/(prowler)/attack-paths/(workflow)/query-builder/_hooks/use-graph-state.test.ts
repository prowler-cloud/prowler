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

  it("clears the selected node when fresh graph data loads", () => {
    // Given - a node is selected in the current graph
    useGraphStore.getState().setSelectedNodeId("resource-a");

    // When - a new query loads
    useGraphStore.getState().setGraphData({ nodes: [], edges: [] }, null);

    // Then
    expect(useGraphStore.getState().selectedNodeId).toBeNull();
  });

  it("expands multiple resource classes at once", () => {
    // When
    useGraphStore.getState().toggleExpandedClass("0::AWSRole");
    useGraphStore.getState().toggleExpandedClass("1::AWSPolicy");

    // Then
    expect(Array.from(useGraphStore.getState().expandedClasses)).toEqual([
      "0::AWSRole",
      "1::AWSPolicy",
    ]);
  });

  it("closes an expanded class when toggled again", () => {
    // Given
    useGraphStore.getState().toggleExpandedClass("0::AWSRole");

    // When
    useGraphStore.getState().toggleExpandedClass("0::AWSRole");

    // Then
    expect(useGraphStore.getState().expandedClasses.size).toBe(0);
  });

  it("collapses every expanded class", () => {
    // Given
    useGraphStore.getState().toggleExpandedClass("0::AWSRole");
    useGraphStore.getState().toggleExpandedClass("1::AWSPolicy");

    // When
    useGraphStore.getState().collapseAllClasses();

    // Then
    expect(useGraphStore.getState().expandedClasses.size).toBe(0);
  });

  it("clears expanded classes when fresh graph data loads", () => {
    // Given
    useGraphStore.getState().toggleExpandedClass("0::AWSRole");

    // When
    useGraphStore.getState().setGraphData({ nodes: [], edges: [] }, null);

    // Then
    expect(useGraphStore.getState().expandedClasses.size).toBe(0);
  });
});
