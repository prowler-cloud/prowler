import { create } from "zustand";

import type { JiraDispatchModalPayload } from "@/types/jira-dispatch";

interface JiraDispatchStoreState {
  activePayload: JiraDispatchModalPayload | null;
  openJiraDispatch: (payload: JiraDispatchModalPayload) => void;
  closeJiraDispatch: () => void;
}

// Jira dispatch is ephemeral and globally hosted so every action uses one modal.
export const useJiraDispatchStore = create<JiraDispatchStoreState>((set) => ({
  activePayload: null,
  openJiraDispatch: (activePayload) => set({ activePayload }),
  closeJiraDispatch: () => set({ activePayload: null }),
}));
