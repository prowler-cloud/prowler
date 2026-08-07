type PanelChatMessageStateListener = () => void;

const listeners = new Set<PanelChatMessageStateListener>();
let hasMessages = false;
let activeSessionId: string | null = null;

export function getPanelChatHasMessages(): boolean {
  return hasMessages;
}

export function subscribePanelChatHasMessages(
  listener: PanelChatMessageStateListener,
): () => void {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

export function getPanelChatActiveSessionId(): string | null {
  return activeSessionId;
}

interface PanelChatMessageState {
  hasMessages: boolean;
  activeSessionId: string | null;
}

export function setPanelChatMessageState(
  nextState: PanelChatMessageState,
): void {
  if (
    hasMessages === nextState.hasMessages &&
    activeSessionId === nextState.activeSessionId
  ) {
    return;
  }

  hasMessages = nextState.hasMessages;
  activeSessionId = nextState.activeSessionId;
  listeners.forEach((listener) => listener());
}

export function resetPanelChatMessageState(): void {
  setPanelChatMessageState({ hasMessages: false, activeSessionId: null });
}
