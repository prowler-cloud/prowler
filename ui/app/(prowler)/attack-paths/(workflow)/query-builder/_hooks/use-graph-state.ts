"use client";

import { create } from "zustand";

import type {
  AttackPathGraphData,
  GraphNode,
  GraphState,
} from "@/types/attack-paths";

import { computeFilteredSubgraph } from "../_lib";

interface FilteredViewState {
  isFilteredView: boolean;
  filteredNodeId: string | null;
  fullData: AttackPathGraphData | null; // Original data before filtering
  // Tier 1 expansion state: which resource nodes have their findings revealed.
  // Lives in the store (not local component state) so it survives the data
  // swaps that happen when entering/exiting filtered view. Reset only on
  // fresh data loads (new query / scan) — see `setGraphData`.
  expandedResources: Set<string>;
}

interface GraphStore extends GraphState, FilteredViewState {
  setGraphData: (data: AttackPathGraphData) => void;
  setSelectedNodeId: (nodeId: string | null) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setFilteredView: (
    isFiltered: boolean,
    nodeId: string | null,
    filteredData: AttackPathGraphData | null,
    fullData: AttackPathGraphData | null,
  ) => void;
  toggleExpandedResource: (resourceId: string) => void;
  reset: () => void;
}

const initialState: GraphState & FilteredViewState = {
  data: null,
  selectedNodeId: null,
  loading: false,
  error: null,
  isFilteredView: false,
  filteredNodeId: null,
  fullData: null,
  expandedResources: new Set(),
};

export const useGraphStore = create<GraphStore>((set) => ({
  ...initialState,
  setGraphData: (data) =>
    set({
      data,
      fullData: null,
      error: null,
      isFilteredView: false,
      filteredNodeId: null,
      // Fresh data → drop any stale expansion from the previous graph.
      expandedResources: new Set(),
    }),
  setSelectedNodeId: (nodeId) => set({ selectedNodeId: nodeId }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setFilteredView: (isFiltered, nodeId, filteredData, fullData) =>
    set({
      isFilteredView: isFiltered,
      filteredNodeId: nodeId,
      data: filteredData,
      fullData,
      selectedNodeId: nodeId,
    }),
  toggleExpandedResource: (resourceId) =>
    set((state) => {
      const next = new Set(state.expandedResources);
      if (next.has(resourceId)) {
        next.delete(resourceId);
      } else {
        next.add(resourceId);
      }
      return { expandedResources: next };
    }),
  reset: () => set(initialState),
}));

/**
 * Custom hook for managing graph visualization state
 * Handles graph data, node selection, zoom/pan, loading states, and filtered view
 */
export const useGraphState = () => {
  const store = useGraphStore();

  // Zustand store methods are stable, no need to memoize
  const updateGraphData = (data: AttackPathGraphData) => {
    store.setGraphData(data);
  };

  const selectNode = (nodeId: string | null) => {
    store.setSelectedNodeId(nodeId);
  };

  const getSelectedNode = (): GraphNode | null => {
    if (!store.data?.nodes || !store.selectedNodeId) return null;
    return (
      store.data.nodes.find((node) => node.id === store.selectedNodeId) || null
    );
  };

  const startLoading = () => {
    store.setLoading(true);
  };

  const stopLoading = () => {
    store.setLoading(false);
  };

  const setError = (error: string | null) => {
    store.setError(error);
  };

  const resetGraph = () => {
    store.reset();
  };

  const clearGraph = () => {
    store.setGraphData({ nodes: [], edges: [] });
    store.setSelectedNodeId(null);
    store.setFilteredView(false, null, null, null);
  };

  /**
   * Enter filtered view mode - redraws graph with only the selected path
   * Stores full data so we can restore it when exiting filtered view
   */
  const enterFilteredView = (nodeId: string) => {
    if (!store.data) return;

    // Use fullData if we're already in filtered view, otherwise use current data
    const sourceData = store.fullData || store.data;
    const filteredData = computeFilteredSubgraph(sourceData, nodeId);
    store.setFilteredView(true, nodeId, filteredData, sourceData);
  };

  /**
   * Exit filtered view mode - restore full graph data
   */
  const exitFilteredView = () => {
    if (!store.isFilteredView || !store.fullData) return;
    store.setFilteredView(false, null, store.fullData, null);
  };

  /**
   * Get the node that was used to filter the view
   */
  const getFilteredNode = (): GraphNode | null => {
    if (!store.isFilteredView || !store.filteredNodeId) return null;
    // Look in fullData since that's where the original node data is
    const sourceData = store.fullData || store.data;
    if (!sourceData) return null;
    return (
      sourceData.nodes.find((node) => node.id === store.filteredNodeId) || null
    );
  };

  return {
    data: store.data,
    fullData: store.fullData,
    selectedNodeId: store.selectedNodeId,
    selectedNode: getSelectedNode(),
    loading: store.loading,
    error: store.error,
    isFilteredView: store.isFilteredView,
    filteredNodeId: store.filteredNodeId,
    filteredNode: getFilteredNode(),
    expandedResources: store.expandedResources,
    toggleExpandedResource: store.toggleExpandedResource,
    updateGraphData,
    selectNode,
    startLoading,
    stopLoading,
    setError,
    resetGraph,
    clearGraph,
    enterFilteredView,
    exitFilteredView,
  };
};
