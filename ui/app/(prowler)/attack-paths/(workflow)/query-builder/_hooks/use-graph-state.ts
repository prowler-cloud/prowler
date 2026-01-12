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
  visibleNodeIds: Set<string> | null; // null means all nodes visible
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
    visibleNodeIds: Set<string> | null,
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
  visibleNodeIds: null,
};

const useGraphStore = create<GraphStore>((set) => ({
  ...initialState,
  setGraphData: (data) => set({ data, error: null, isFilteredView: false, filteredNodeId: null, visibleNodeIds: null }),
  setSelectedNodeId: (nodeId) => set({ selectedNodeId: nodeId }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setZoom: (zoomLevel) => set({ zoomLevel }),
  setPan: (panX, panY) => set({ panX, panY }),
  setFilteredView: (isFiltered, nodeId, visibleNodeIds) =>
    set({ isFilteredView: isFiltered, filteredNodeId: nodeId, visibleNodeIds, selectedNodeId: nodeId }),
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
 * Compute the set of visible node IDs for a filtered view.
 * This follows the directed graph structure of attack paths:
 * - Upstream: traces back to the root (AWS Account)
 * - Downstream: traces forward to leaf nodes
 * - Also includes findings connected to the selected node
 */
function computeVisibleNodeIds(
  fullData: AttackPathGraphData,
  targetNodeId: string,
): Set<string> {
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

  const visibleNodes = new Set<string>();
  visibleNodes.add(targetNodeId);

  // Traverse upstream (backward) - find all ancestors
  const traverseUpstream = (nodeId: string) => {
    const sources = backwardEdges.get(nodeId);
    if (sources) {
      sources.forEach((sourceId) => {
        if (!visibleNodes.has(sourceId)) {
          visibleNodes.add(sourceId);
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
        if (!visibleNodes.has(targetId)) {
          visibleNodes.add(targetId);
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
      visibleNodes.add(targetId);
    }
    if (targetId === targetNodeId && sourceIsFinding) {
      visibleNodes.add(sourceId);
    }
  });

  return visibleNodes;
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
    store.setFilteredView(false, null, null);
  };

  /**
   * Enter filtered view mode - computes visible nodes without changing graph data
   * This allows D3 to animate visibility changes instead of rebuilding the DOM
   */
  const enterFilteredView = (nodeId: string) => {
    if (!store.data) return;

    const visibleNodeIds = computeVisibleNodeIds(store.data, nodeId);
    store.setFilteredView(true, nodeId, visibleNodeIds);
  };

  /**
   * Exit filtered view mode - show all nodes again
   */
  const exitFilteredView = () => {
    if (!store.isFilteredView) return;
    store.setFilteredView(false, null, null);
  };

  /**
   * Get the node that was used to filter the view
   */
  const getFilteredNode = (): GraphNode | null => {
    if (!store.isFilteredView || !store.filteredNodeId || !store.data)
      return null;
    return (
      store.data.nodes.find((node) => node.id === store.filteredNodeId) || null
    );
  };

  return {
    data: store.data,
    selectedNodeId: store.selectedNodeId,
    selectedNode: getSelectedNode(),
    loading: store.loading,
    error: store.error,
    zoomLevel: store.zoomLevel,
    panX: store.panX,
    panY: store.panY,
    isFilteredView: store.isFilteredView,
    filteredNodeId: store.filteredNodeId,
    visibleNodeIds: store.visibleNodeIds,
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
