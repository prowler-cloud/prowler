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

  it("prunes findings-expansion and selection for members a collapsed class hides", () => {
    // Given - a member of an expanded class has its findings open and is selected
    useGraphStore.getState().toggleExpandedClass("1::AWSPolicy");
    useGraphStore.getState().toggleExpandedResource("pol-1");
    useGraphStore.getState().setSelectedNodeId("pol-1");

    // When - the class collapses, hiding pol-1
    useGraphStore.getState().collapseAllClasses(["pol-1", "pol-2"]);

    // Then - no stale state survives to restore on re-expand
    expect(useGraphStore.getState().expandedResources.size).toBe(0);
    expect(useGraphStore.getState().selectedNodeId).toBeNull();
  });

  it("keeps selection and expansion for members outside the collapsed class", () => {
    // Given
    useGraphStore.getState().toggleExpandedResource("role-1");
    useGraphStore.getState().setSelectedNodeId("role-1");

    // When - a different class collapses (role-1 is not among its members)
    useGraphStore.getState().collapseAllClasses(["pol-1", "pol-2"]);

    // Then
    expect(Array.from(useGraphStore.getState().expandedResources)).toEqual([
      "role-1",
    ]);
    expect(useGraphStore.getState().selectedNodeId).toBe("role-1");
  });

  it("prunes hidden-member state when a single class is toggled closed", () => {
    // Given
    useGraphStore.getState().toggleExpandedClass("1::AWSPolicy");
    useGraphStore.getState().toggleExpandedResource("pol-1");
    useGraphStore.getState().setSelectedNodeId("pol-1");

    // When
    useGraphStore.getState().toggleExpandedClass("1::AWSPolicy", ["pol-1"]);

    // Then
    expect(useGraphStore.getState().expandedClasses.size).toBe(0);
    expect(useGraphStore.getState().expandedResources.size).toBe(0);
    expect(useGraphStore.getState().selectedNodeId).toBeNull();
  });
});
