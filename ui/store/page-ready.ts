import { create } from "zustand";

interface PageReadyState {
  // The pathname whose data-fetching content is currently mounted. The replay icon
  // in the navbar is enabled only when this matches the active route, so it stays
  // disabled while a page is still streaming its data.
  readyPath: string | null;

  // Marks the given route as loaded (called when a page's post-Suspense content mounts).
  markReady: (path: string) => void;
  // Clears readiness for the given route, but only if it is still the current one —
  // a newer page may already have marked itself ready during a fast navigation.
  clearReady: (path: string) => void;
}

// Ephemeral, NOT persisted: readiness is a per-render signal, never durable.
export const usePageReadyStore = create<PageReadyState>((set) => ({
  readyPath: null,

  markReady: (path) => set({ readyPath: path }),

  clearReady: (path) =>
    set((state) => (state.readyPath === path ? { readyPath: null } : {})),
}));
