import { create } from "zustand";
import { persist } from "zustand/middleware";

interface PartialScanHintState {
  // True once the user has opened a re-check from any entry point.
  hasSeenRecheckHint: boolean;
  markRecheckHintSeen: () => void;
}

// The "Last seen" icon pulses, like the navbar bell, until the feature has
// been used once; that acknowledgement survives reloads.
export const usePartialScanHintStore = create<PartialScanHintState>()(
  persist(
    (set) => ({
      hasSeenRecheckHint: false,
      markRecheckHintSeen: () => set({ hasSeenRecheckHint: true }),
    }),
    { name: "partial-scan-hint-store" },
  ),
);
