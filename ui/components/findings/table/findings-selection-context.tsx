"use client";

import { createContext, useContext } from "react";

interface FindingsSelectionContextValue {
  selectedFindingIds: string[];

  selectedFindings: any[];
  clearSelection: () => void;
  isSelected: (id: string) => boolean;
}

export const FindingsSelectionContext =
  createContext<FindingsSelectionContextValue>({
    selectedFindingIds: [],
    selectedFindings: [],
    clearSelection: () => {},
    isSelected: () => false,
  });

export function useFindingsSelection() {
  const context = useContext(FindingsSelectionContext);
  if (!context) {
    throw new Error(
      "useFindingsSelection must be used within a FindingsSelectionProvider",
    );
  }
  return context;
}
