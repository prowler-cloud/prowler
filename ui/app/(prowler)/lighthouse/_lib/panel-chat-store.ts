import {
  createLighthouseChatStore,
  type LighthouseChatConfig,
  type LighthouseChatStore,
} from "@/app/(prowler)/lighthouse/_lib/chat-store";

// Module-level singleton: every AI surface outside the /lighthouse page (the
// global side panel and the drawer tabs) binds to this one store, so it is the
// same conversation everywhere and its EventSource survives route navigation
// and panel closes. The page keeps its own per-mount instance (URL-synced).
let panelChatStore: LighthouseChatStore | null = null;

interface PanelChatStoreOptions {
  initialError?: string;
}

export function getOrCreatePanelChatStore(
  config: LighthouseChatConfig,
  options?: PanelChatStoreOptions,
): LighthouseChatStore {
  if (!panelChatStore) {
    panelChatStore = createLighthouseChatStore({
      config,
      syncUrlToSession: false,
      initialError: options?.initialError,
    });
  }
  return panelChatStore;
}

export function getPanelChatStoreIfExists(): LighthouseChatStore | null {
  return panelChatStore;
}

// The config is captured in the store's closure at creation, so a
// configuration change must tear the singleton down and rebuild it.
export function resetPanelChatStore(): void {
  panelChatStore?.getState().destroy();
  panelChatStore = null;
}

export function resetPanelChatStoreForTests(): void {
  resetPanelChatStore();
}
