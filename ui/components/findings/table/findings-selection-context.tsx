"use client";

import { createContext, useContext } from "react";

interface FindingsSelectionContextValue {
  selectedFindingIds: string[];
  selectedFindings: any[];
  clearSelection: () => void;
  isSelected: (id: string) => boolean;
  /** Resolves display IDs (check_ids or resource_ids) into real finding UUIDs for the mute API. */
  resolveMuteIds?: (ids: string[]) => Promise<string[]>;
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
