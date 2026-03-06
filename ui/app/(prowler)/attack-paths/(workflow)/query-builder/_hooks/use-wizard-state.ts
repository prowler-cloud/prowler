"use client";

import { useRouter } from "next/navigation";
import { useCallback } from "react";
import { create } from "zustand";

import type { WizardState } from "@/types/attack-paths";

interface WizardStore extends WizardState {
  setCurrentStep: (step: 1 | 2) => void;
  setSelectedScanId: (scanId: string) => void;
  setSelectedQuery: (queryId: string) => void;
  setQueryParameters: (
    parameters: Record<string, string | number | boolean>,
  ) => void;
  reset: () => void;
}

const initialState: WizardState = {
  currentStep: 1,
  selectedScanId: null,
  selectedQuery: null,
  queryParameters: {},
};

const useWizardStore = create<WizardStore>((set) => ({
  ...initialState,
  setCurrentStep: (step) => set({ currentStep: step }),
  setSelectedScanId: (scanId) => set({ selectedScanId: scanId }),
  setSelectedQuery: (queryId) => set({ selectedQuery: queryId }),
  setQueryParameters: (parameters) => set({ queryParameters: parameters }),
  reset: () => set(initialState),
}));

/**
 * Custom hook for managing Attack Paths wizard state
 * Handles step navigation, scan selection, and query configuration
 */
export const useWizardState = () => {
  const router = useRouter();

  const store = useWizardStore();

  // Derive current step from URL path
  const currentStep: 1 | 2 =
    typeof window !== "undefined"
      ? window.location.pathname.includes("query-builder")
        ? 2
        : 1
      : 1;

  const goToSelectScan = useCallback(() => {
    store.setCurrentStep(1);
    router.push("/attack-paths/select-scan");
  }, [router, store]);

  const goToQueryBuilder = useCallback(
    (scanId: string) => {
      store.setSelectedScanId(scanId);
      store.setCurrentStep(2);
      router.push(`/attack-paths/query-builder?scanId=${scanId}`);
    },
    [router, store],
  );

  const updateQueryParameters = useCallback(
    (parameters: Record<string, string | number | boolean>) => {
      store.setQueryParameters(parameters);
    },
    [store],
  );

  const getScanIdFromUrl = useCallback(() => {
    const params = new URLSearchParams(
      typeof window !== "undefined" ? window.location.search : "",
    );
    return params.get("scanId") || store.selectedScanId;
  }, [store.selectedScanId]);

  return {
    currentStep,
    selectedScanId: store.selectedScanId || getScanIdFromUrl(),
    selectedQuery: store.selectedQuery,
    queryParameters: store.queryParameters,
    goToSelectScan,
    goToQueryBuilder,
    setSelectedQuery: store.setSelectedQuery,
    updateQueryParameters,
    reset: store.reset,
  };
};
