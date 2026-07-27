import { beforeEach, describe, expect, it } from "vitest";

import { ATTACK_PATH_QUERY_KIND } from "@/types/attack-paths";

import { useGraphStore } from "./use-graph-state";

const emptyGraph = { nodes: [], relationships: [] };
const predefinedExecution = {
  queryId: "aws-public-s3-buckets",
  queryLabel: "Public S3 buckets",
  queryKind: ATTACK_PATH_QUERY_KIND.PREDEFINED,
  parameters: {},
};

describe("useGraphStore", () => {
  beforeEach(() => {
    useGraphStore.getState().reset();
  });

  it("stores the graph and its query execution metadata atomically", () => {
    // Given
    const store = useGraphStore.getState();

    // When
    store.setGraphData(emptyGraph, predefinedExecution);

    // Then
    expect(useGraphStore.getState()).toMatchObject({
      data: emptyGraph,
      execution: predefinedExecution,
    });
  });

  it("clears query execution metadata with the graph", () => {
    // Given
    const store = useGraphStore.getState();
    store.setGraphData(emptyGraph, predefinedExecution);

    // When
    useGraphStore.getState().reset();

    // Then
    expect(useGraphStore.getState()).toMatchObject({
      data: null,
      execution: null,
    });
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
