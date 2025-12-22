"use client";

import { createContext, useContext } from "react";

import { FindingProps } from "@/types";

interface FindingsSelectionContextValue {
  selectedFindingIds: string[];
  selectedFindings: FindingProps[];
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
