import { create } from "zustand";
import { createJSONStorage, persist } from "zustand/middleware";

import { APP_SIDEBAR_MODE, type AppSidebarMode } from "./types";

interface PersistedAppSidebarState {
  mode: AppSidebarMode;
}

interface AppSidebarModeStore extends PersistedAppSidebarState {
  setMode: (mode: AppSidebarMode) => void;
}

function isAppSidebarMode(value: unknown): value is AppSidebarMode {
  return Object.values(APP_SIDEBAR_MODE).some((mode) => mode === value);
}

export function migrateAppSidebarState(
  persistedState: unknown,
): PersistedAppSidebarState {
  if (typeof persistedState !== "object" || persistedState === null) {
    return { mode: APP_SIDEBAR_MODE.BROWSE };
  }

  if ("mode" in persistedState && isAppSidebarMode(persistedState.mode)) {
    return { mode: persistedState.mode };
  }

  if (
    "navigationMode" in persistedState &&
    isAppSidebarMode(persistedState.navigationMode)
  ) {
    return { mode: persistedState.navigationMode };
  }

  return { mode: APP_SIDEBAR_MODE.BROWSE };
}

export const useAppSidebarMode = create<AppSidebarModeStore>()(
  persist(
    (set) => ({
      mode: APP_SIDEBAR_MODE.BROWSE,
      setMode: (mode) => set({ mode }),
    }),
    {
      name: "sidebar",
      storage: createJSONStorage(() => localStorage),
      merge: (persistedState, currentState) => ({
        ...currentState,
        ...migrateAppSidebarState(persistedState),
      }),
    },
  ),
);
