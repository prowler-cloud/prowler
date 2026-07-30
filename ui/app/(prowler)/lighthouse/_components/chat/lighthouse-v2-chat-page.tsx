"use client";

import { useState } from "react";

import {
  createLighthouseChatStore,
  type LighthouseChatStore,
} from "@/app/(prowler)/lighthouse/_lib/chat-store";
import {
  getPanelChatStoreForSession,
  isPanelChatStore,
} from "@/app/(prowler)/lighthouse/_lib/panel-chat-store";
import {
  onLighthouseV2NewChat,
  onLighthouseV2SessionArchived,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import type {
  LighthouseV2Configuration,
  LighthouseV2Message,
  LighthouseV2ProviderType,
  LighthouseV2SupportedModel,
  LighthouseV2SupportedProvider,
} from "@/app/(prowler)/lighthouse/_types";
import { useMountEffect } from "@/hooks/use-mount-effect";

import { LighthouseChatStoreProvider } from "./lighthouse-chat-store-provider";
import {
  LIGHTHOUSE_CHAT_SURFACE,
  LighthouseV2ChatView,
} from "./lighthouse-v2-chat-view";

interface LighthouseV2ChatPageProps {
  configurations: LighthouseV2Configuration[];
  modelsByProvider: Record<
    LighthouseV2ProviderType,
    LighthouseV2SupportedModel[]
  >;
  supportedProviders: LighthouseV2SupportedProvider[];
  initialSessionId?: string;
  initialMessages: LighthouseV2Message[];
  initialPrompt?: string;
  initialError?: string;
}

export function LighthouseV2ChatPage({
  configurations,
  modelsByProvider,
  supportedProviders,
  initialSessionId,
  initialMessages,
  initialPrompt,
  initialError,
}: LighthouseV2ChatPageProps) {
  // Navigation from the side panel transfers its live store so drafts,
  // streamed output and the open EventSource continue without a snapshot gap.
  // Direct/session-mismatched navigation builds the normal page-owned store.
  const [store] = useState<LighthouseChatStore>(() => {
    const panelStore =
      initialPrompt === undefined
        ? getPanelChatStoreForSession(initialSessionId)
        : null;
    return (
      panelStore ??
      createLighthouseChatStore({
        config: { configurations, modelsByProvider, supportedProviders },
        syncUrlToSession: true,
        initialSessionId,
        initialMessages,
        initialInput: initialPrompt,
        initialError,
      })
    );
  });
  const reusesPanelStore = isPanelChatStore(store);

  // A reused panel store returns to panel URL semantics when the page leaves;
  // a page-owned store closes its EventSource as before.
  useMountEffect(() => {
    if (reusesPanelStore) {
      store.getState().setSessionUrlSyncEnabled(true);
    }
    return () => {
      if (reusesPanelStore) {
        store.getState().setSessionUrlSyncEnabled(false);
        return;
      }
      store.getState().destroy();
    };
  });

  // The sidebar "+" can't rely on routing to reset the latest conversation (its
  // URL was set via replaceState, invisible to Next's router), so reset in place.
  useMountEffect(() => {
    const unsubscribeNewChat = onLighthouseV2NewChat(() =>
      store.getState().resetToNewChat(),
    );
    const unsubscribeSessionArchived = onLighthouseV2SessionArchived(
      (sessionId) => store.getState().handleSessionArchived(sessionId),
    );
    return () => {
      unsubscribeNewChat();
      unsubscribeSessionArchived();
    };
  });

  return (
    <LighthouseChatStoreProvider store={store}>
      <LighthouseV2ChatView surface={LIGHTHOUSE_CHAT_SURFACE.PAGE} />
    </LighthouseChatStoreProvider>
  );
}
