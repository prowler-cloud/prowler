"use client";

import { create } from "zustand";

import type {
  AttackPathGraphData,
  GraphNode,
  GraphState,
} from "@/types/attack-paths";

interface FilteredViewState {
  isFilteredView: boolean;
  filteredNodeId: string | null;
  fullData: AttackPathGraphData | null; // Original data before filtering
}

interface GraphStore extends GraphState, FilteredViewState {
  setGraphData: (data: AttackPathGraphData) => void;
  setSelectedNodeId: (nodeId: string | null) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setZoom: (zoomLevel: number) => void;
  setPan: (panX: number, panY: number) => void;
  setFilteredView: (
    isFiltered: boolean,
    nodeId: string | null,
    filteredData: AttackPathGraphData | null,
    fullData: AttackPathGraphData | null,
  ) => void;
  reset: () => void;
}

const initialState: GraphState & FilteredViewState = {
  data: null,
  selectedNodeId: null,
  loading: false,
  error: null,
  zoomLevel: 1,
  panX: 0,
  panY: 0,
  isFilteredView: false,
  filteredNodeId: null,
  fullData: null,
};

const useGraphStore = create<GraphStore>((set) => ({
  ...initialState,
  setGraphData: (data) => set({ data, fullData: null, error: null, isFilteredView: false, filteredNodeId: null }),
  setSelectedNodeId: (nodeId) => set({ selectedNodeId: nodeId }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setZoom: (zoomLevel) => set({ zoomLevel }),
  setPan: (panX, panY) => set({ panX, panY }),
  setFilteredView: (isFiltered, nodeId, filteredData, fullData) =>
    set({ isFilteredView: isFiltered, filteredNodeId: nodeId, data: filteredData, fullData, selectedNodeId: nodeId }),
  reset: () => set(initialState),
}));

/**
 * Helper to get edge source/target ID from string or object
 */
function getEdgeNodeId(nodeRef: string | object): string {
  if (typeof nodeRef === "string") {
    return nodeRef;
  }
  return (nodeRef as GraphNode).id;
}

/**
 * Compute a filtered subgraph containing only the path through the target node.
 * This follows the directed graph structure of attack paths:
 * - Upstream: traces back to the root (AWS Account)
 * - Downstream: traces forward to leaf nodes
 * - Also includes findings connected to the selected node
 */
function computeFilteredSubgraph(
  fullData: AttackPathGraphData,
  targetNodeId: string,
): AttackPathGraphData {
  const nodes = fullData.nodes;
  const edges = fullData.edges || [];

  // Build directed adjacency lists
  const forwardEdges = new Map<string, Set<string>>(); // source -> targets
  const backwardEdges = new Map<string, Set<string>>(); // target -> sources
  nodes.forEach((node) => {
    forwardEdges.set(node.id, new Set());
    backwardEdges.set(node.id, new Set());
  });

  edges.forEach((edge) => {
    const sourceId = getEdgeNodeId(edge.source);
    const targetId = getEdgeNodeId(edge.target);
    forwardEdges.get(sourceId)?.add(targetId);
    backwardEdges.get(targetId)?.add(sourceId);
  });

  const visibleNodeIds = new Set<string>();
  visibleNodeIds.add(targetNodeId);

  // Traverse upstream (backward) - find all ancestors
  const traverseUpstream = (nodeId: string) => {
    const sources = backwardEdges.get(nodeId);
    if (sources) {
      sources.forEach((sourceId) => {
        if (!visibleNodeIds.has(sourceId)) {
          visibleNodeIds.add(sourceId);
          traverseUpstream(sourceId);
        }
      });
    }
  };

  // Traverse downstream (forward) - find all descendants
  const traverseDownstream = (nodeId: string) => {
    const targets = forwardEdges.get(nodeId);
    if (targets) {
      targets.forEach((targetId) => {
        if (!visibleNodeIds.has(targetId)) {
          visibleNodeIds.add(targetId);
          traverseDownstream(targetId);
        }
      });
    }
  };

  // Start traversal from the target node
  traverseUpstream(targetNodeId);
  traverseDownstream(targetNodeId);

  // Also include findings directly connected to the selected node
  edges.forEach((edge) => {
    const sourceId = getEdgeNodeId(edge.source);
    const targetId = getEdgeNodeId(edge.target);
    const sourceNode = nodes.find((n) => n.id === sourceId);
    const targetNode = nodes.find((n) => n.id === targetId);

    const sourceIsFinding = sourceNode?.labels.some((l) =>
      l.toLowerCase().includes("finding"),
    );
    const targetIsFinding = targetNode?.labels.some((l) =>
      l.toLowerCase().includes("finding"),
    );

    // Include findings connected to the selected node
    if (sourceId === targetNodeId && targetIsFinding) {
      visibleNodeIds.add(targetId);
    }
    if (targetId === targetNodeId && sourceIsFinding) {
      visibleNodeIds.add(sourceId);
    }
  });

  // Filter nodes and edges to only include visible ones
  const filteredNodes = nodes.filter((node) => visibleNodeIds.has(node.id));
  const filteredEdges = edges.filter((edge) => {
    const sourceId = getEdgeNodeId(edge.source);
    const targetId = getEdgeNodeId(edge.target);
    return visibleNodeIds.has(sourceId) && visibleNodeIds.has(targetId);
  });

  return {
    nodes: filteredNodes,
    edges: filteredEdges,
  };
}

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

  const updateZoomAndPan = (zoomLevel: number, panX: number, panY: number) => {
    store.setZoom(zoomLevel);
    store.setPan(panX, panY);
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
    zoomLevel: store.zoomLevel,
    panX: store.panX,
    panY: store.panY,
    isFilteredView: store.isFilteredView,
    filteredNodeId: store.filteredNodeId,
    filteredNode: getFilteredNode(),
    updateGraphData,
    selectNode,
    startLoading,
    stopLoading,
    setError,
    updateZoomAndPan,
    resetGraph,
    clearGraph,
    enterFilteredView,
    exitFilteredView,
  };
};
