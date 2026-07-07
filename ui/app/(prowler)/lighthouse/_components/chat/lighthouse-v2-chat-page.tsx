"use client";

import { useRef, useState } from "react";

import {
  createLighthouseChatStore,
  type LighthouseChatStore,
} from "@/app/(prowler)/lighthouse/_lib/chat-store";
import {
  LIGHTHOUSE_V2_NEW_CHAT_EVENT,
  LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
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
  // Per-mount store instance: page.tsx keys this component by session/prompt,
  // so a route-level session change builds a fresh store (matching the old
  // useState-based behavior), while the URL keeps syncing via replaceState.
  const [store] = useState<LighthouseChatStore>(() =>
    createLighthouseChatStore({
      config: { configurations, modelsByProvider, supportedProviders },
      syncUrlToSession: true,
      initialSessionId,
      initialMessages,
      initialError,
    }),
  );
  const initialPromptSentRef = useRef(false);

  // Close any open EventSource when the chat unmounts (e.g. route/session change).
  useMountEffect(() => {
    return () => store.getState().destroy();
  });

  useMountEffect(() => {
    if (initialPrompt && !initialPromptSentRef.current) {
      initialPromptSentRef.current = true;
      void store.getState().submitMessage(initialPrompt);
    }
  });

  // The sidebar "+" can't rely on routing to reset the latest conversation (its
  // URL was set via replaceState, invisible to Next's router), so reset in place.
  useMountEffect(() => {
    const handleNewChat = () => store.getState().resetToNewChat();
    const handleSessionArchived = (event: Event) => {
      const archivedId = (event as CustomEvent<{ sessionId: string }>).detail
        ?.sessionId;
      if (archivedId) {
        store.getState().handleSessionArchived(archivedId);
      }
    };

    window.addEventListener(LIGHTHOUSE_V2_NEW_CHAT_EVENT, handleNewChat);
    window.addEventListener(
      LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
      handleSessionArchived,
    );
    return () => {
      window.removeEventListener(LIGHTHOUSE_V2_NEW_CHAT_EVENT, handleNewChat);
      window.removeEventListener(
        LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
        handleSessionArchived,
      );
    };
  });

  return (
    <LighthouseChatStoreProvider store={store}>
      <LighthouseV2ChatView surface={LIGHTHOUSE_CHAT_SURFACE.PAGE} />
    </LighthouseChatStoreProvider>
  );
}
