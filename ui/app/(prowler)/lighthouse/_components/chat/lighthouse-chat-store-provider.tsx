"use client";

import { createContext, type ReactNode, useContext } from "react";
import { useStore } from "zustand";

import type {
  LighthouseChatState,
  LighthouseChatStore,
} from "@/app/(prowler)/lighthouse/_lib/chat-store";

const LighthouseChatStoreContext = createContext<LighthouseChatStore | null>(
  null,
);

interface LighthouseChatStoreProviderProps {
  store: LighthouseChatStore;
  children: ReactNode;
}

export function LighthouseChatStoreProvider({
  store,
  children,
}: LighthouseChatStoreProviderProps) {
  return (
    <LighthouseChatStoreContext.Provider value={store}>
      {children}
    </LighthouseChatStoreContext.Provider>
  );
}

export function useLighthouseChatStore<T>(
  selector: (state: LighthouseChatState) => T,
): T {
  const store = useContext(LighthouseChatStoreContext);
  if (!store) {
    throw new Error(
      "useLighthouseChatStore must be used within LighthouseChatStoreProvider",
    );
  }
  return useStore(store, selector);
}
