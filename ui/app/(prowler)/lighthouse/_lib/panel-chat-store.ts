import {
  createLighthouseChatStore,
  type LighthouseChatConfig,
  type LighthouseChatSubmission,
  type LighthouseChatStore,
} from "@/app/(prowler)/lighthouse/_lib/chat-store";
import type { LighthouseContextEnvelope } from "@/types/lighthouse-context";
import type { LighthouseSkillDefinition } from "@/types/lighthouse-skills";

// Module-level singleton: the global side panel keeps the same conversation
// while switching between Details and Lighthouse AI, across route navigation
// and panel closes. The full-page route can reuse it for the same conversation.
let panelChatStore: LighthouseChatStore | null = null;
let pendingPanelChatMessage: LighthouseChatSubmission | null = null;

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

export function requestPanelChatMessage(
  displayText: string,
  context?: LighthouseContextEnvelope,
): void {
  requestPanelChatSubmission({ displayText, ...(context ? { context } : {}) });
}

// Launching a skill is a regular panel chat message whose display text is the
// skill name; the skill definition rides along so the prompt and the ui_skill
// ref are attached at submit time.
export function requestPanelSkillLaunch(
  skill: LighthouseSkillDefinition,
  context?: LighthouseContextEnvelope,
): void {
  requestPanelChatSubmission({
    displayText: skill.name,
    ...(context ? { context } : {}),
    skill,
  });
}

function requestPanelChatSubmission(
  submission: LighthouseChatSubmission,
): void {
  if (panelChatStore) {
    const chatState = panelChatStore.getState();
    const hasActiveConversation =
      chatState.activeSessionId !== null ||
      chatState.messages.length > 0 ||
      chatState.streamState.activeTaskId !== null ||
      chatState.isSubmitting;
    if (hasActiveConversation) {
      chatState.resetToNewChat();
    }
    void panelChatStore
      .getState()
      .submitMessage(
        submission.displayText,
        submission.context,
        submission.skill,
      );
    return;
  }

  pendingPanelChatMessage = submission;
}

export function flushPendingPanelChatMessage(): void {
  if (!panelChatStore || !pendingPanelChatMessage) return;

  const message = pendingPanelChatMessage;
  pendingPanelChatMessage = null;
  void panelChatStore
    .getState()
    .submitMessage(message.displayText, message.context, message.skill);
}

// Lets the full-page surface reuse the singleton only when both surfaces point
// at the same conversation. This is intentionally a pure lookup: React may
// run state initializers twice in Strict Mode.
export function getPanelChatStoreForSession(
  initialSessionId?: string,
): LighthouseChatStore | null {
  if (!panelChatStore) return null;
  const expectedSessionId = initialSessionId ?? null;
  if (panelChatStore.getState().activeSessionId !== expectedSessionId) {
    return null;
  }
  return panelChatStore;
}

export function isPanelChatStore(store: LighthouseChatStore): boolean {
  return panelChatStore === store;
}

// The config is captured in the store's closure at creation, so a
// configuration change must tear the singleton down and rebuild it.
export function resetPanelChatStore(): void {
  panelChatStore?.getState().destroy();
  panelChatStore = null;
}

export function resetPanelChatStoreForTests(): void {
  resetPanelChatStore();
  pendingPanelChatMessage = null;
}
