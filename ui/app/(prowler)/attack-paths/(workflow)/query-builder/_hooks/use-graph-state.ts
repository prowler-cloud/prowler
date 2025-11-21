"use client";

import { useCallback } from "react";
import { create } from "zustand";

import type {
  AttackPathGraphData,
  GraphNode,
  GraphState,
} from "@/types/attack-paths";

interface GraphStore extends GraphState {
  setGraphData: (data: AttackPathGraphData) => void;
  setSelectedNodeId: (nodeId: string | null) => void;
  setLoading: (loading: boolean) => void;
  setError: (error: string | null) => void;
  setZoom: (zoomLevel: number) => void;
  setPan: (panX: number, panY: number) => void;
  reset: () => void;
}

const initialState: GraphState = {
  data: null,
  selectedNodeId: null,
  loading: false,
  error: null,
  zoomLevel: 1,
  panX: 0,
  panY: 0,
};

const useGraphStore = create<GraphStore>((set) => ({
  ...initialState,
  setGraphData: (data) => set({ data, error: null }),
  setSelectedNodeId: (nodeId) => set({ selectedNodeId: nodeId }),
  setLoading: (loading) => set({ loading }),
  setError: (error) => set({ error }),
  setZoom: (zoomLevel) => set({ zoomLevel }),
  setPan: (panX, panY) => set({ panX, panY }),
  reset: () => set(initialState),
}));

/**
 * Custom hook for managing graph visualization state
 * Handles graph data, node selection, zoom/pan, and loading states
 */
export const useGraphState = () => {
  const store = useGraphStore();

  const updateGraphData = useCallback(
    (data: AttackPathGraphData) => {
      store.setGraphData(data);
    },
    [store.setGraphData],
  );

  const selectNode = useCallback(
    (nodeId: string | null) => {
      store.setSelectedNodeId(nodeId);
    },
    [store.setSelectedNodeId],
  );

  const getSelectedNode = useCallback((): GraphNode | null => {
    if (!store.data?.nodes || !store.selectedNodeId) return null;
    return (
      store.data.nodes.find((node) => node.id === store.selectedNodeId) || null
    );
  }, [store.data?.nodes, store.selectedNodeId]);

  const startLoading = useCallback(() => {
    store.setLoading(true);
  }, [store.setLoading]);

  const stopLoading = useCallback(() => {
    store.setLoading(false);
  }, [store.setLoading]);

  const setError = useCallback(
    (error: string | null) => {
      store.setError(error);
    },
    [store.setError],
  );

  const updateZoomAndPan = useCallback(
    (zoomLevel: number, panX: number, panY: number) => {
      store.setZoom(zoomLevel);
      store.setPan(panX, panY);
    },
    [store.setZoom, store.setPan],
  );

  const resetGraph = useCallback(() => {
    store.reset();
  }, [store.reset]);

  const clearGraph = useCallback(() => {
    store.setGraphData({ nodes: [], edges: [] });
    store.setSelectedNodeId(null);
  }, [store.setGraphData, store.setSelectedNodeId]);

  return {
    data: store.data,
    selectedNodeId: store.selectedNodeId,
    selectedNode: getSelectedNode(),
    loading: store.loading,
    error: store.error,
    zoomLevel: store.zoomLevel,
    panX: store.panX,
    panY: store.panY,
    updateGraphData,
    selectNode,
    startLoading,
    stopLoading,
    setError,
    updateZoomAndPan,
    resetGraph,
    clearGraph,
  };
};
