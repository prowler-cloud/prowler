import {
  createLighthouseChatStore,
  type LighthouseChatConfig,
  type LighthouseChatStore,
} from "@/app/(prowler)/lighthouse/_lib/chat-store";

// Module-level singleton: the global side panel keeps the same conversation
// while switching between Details and Lighthouse AI, across route navigation
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

// The config is captured in the store's closure at creation, so a
// configuration change must tear the singleton down and rebuild it.
export function resetPanelChatStore(): void {
  panelChatStore?.getState().destroy();
  panelChatStore = null;
}

export function resetPanelChatStoreForTests(): void {
  resetPanelChatStore();
}
