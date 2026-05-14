"use client";

import { createContext, useContext } from "react";

import { FindingGroupRow, FindingProps } from "@/types";

interface FindingsSelectionContextValue {
  selectedFindingIds: string[];
  selectedFindings: (FindingProps | FindingGroupRow)[];
  clearSelection: () => void;
  isSelected: (id: string) => boolean;
  /** Resolves display IDs (check_ids or resource_ids) into real finding UUIDs for the mute API. */
  resolveMuteIds?: (ids: string[]) => Promise<string[]>;
  /**
   * Called after a mute operation completes. Receives the display IDs that
   * were just muted (group check_ids for group rows, finding UUIDs for
   * resource rows). Parents can use them to hide rows optimistically while
   * the server-side reaggregation catches up.
   */
  onMuteComplete?: (mutedIds?: string[]) => void;
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
