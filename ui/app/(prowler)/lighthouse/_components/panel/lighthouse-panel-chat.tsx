"use client";

import Link from "next/link";
import { useState } from "react";

import {
  archiveLighthouseV2Session,
  getLighthouseV2Configurations,
  getLighthouseV2Sessions,
  getLighthouseV2SupportedModels,
  getLighthouseV2SupportedProviders,
} from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2SessionHistory } from "@/app/(prowler)/lighthouse/_components/history";
import type { LighthouseChatConfig } from "@/app/(prowler)/lighthouse/_lib/chat-store";
import { loadLighthouseV2ConnectedModels } from "@/app/(prowler)/lighthouse/_lib/model-loading";
import { getOrCreatePanelChatStore } from "@/app/(prowler)/lighthouse/_lib/panel-chat-store";
import {
  LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
  LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT,
  notifyLighthouseV2SessionArchived,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import type { LighthouseV2Session } from "@/app/(prowler)/lighthouse/_types";
import { LighthouseIconWithAura } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";

import {
  LighthouseChatStoreProvider,
  useLighthouseChatStore,
} from "../chat/lighthouse-chat-store-provider";
import {
  LIGHTHOUSE_CHAT_SURFACE,
  LighthouseV2ChatView,
} from "../chat/lighthouse-v2-chat-view";
import { LighthousePanelChatSkeleton } from "./lighthouse-panel-chat-skeleton";

const PANEL_CHAT_STATUS = {
  LOADING: "loading",
  ERROR: "error",
  NOT_CONFIGURED: "not-configured",
  READY: "ready",
} as const;

interface PanelChatLoadingState {
  status: typeof PANEL_CHAT_STATUS.LOADING;
}

interface PanelChatErrorState {
  status: typeof PANEL_CHAT_STATUS.ERROR;
  message: string;
}

interface PanelChatNotConfiguredState {
  status: typeof PANEL_CHAT_STATUS.NOT_CONFIGURED;
}

interface PanelChatReadyState {
  status: typeof PANEL_CHAT_STATUS.READY;
  config: LighthouseChatConfig;
  modelsError?: string;
}

type PanelChatState =
  | PanelChatLoadingState
  | PanelChatErrorState
  | PanelChatNotConfiguredState
  | PanelChatReadyState;

// Config cache: the panel loads its configs/models lazily on first open (never
// in the layout, so pages don't pay for a panel most sessions never open); the
// cache makes every later mount — reopen, drawer AI tab — instant.
let cachedReadyState: PanelChatReadyState | null = null;

export function resetPanelChatConfigCacheForTests(): void {
  cachedReadyState = null;
}

export function LighthousePanelChat() {
  const [state, setState] = useState<PanelChatState>(
    () => cachedReadyState ?? { status: PANEL_CHAT_STATUS.LOADING },
  );

  const load = async () => {
    setState({ status: PANEL_CHAT_STATUS.LOADING });
    const next = await loadPanelChatState();
    if (next.status === PANEL_CHAT_STATUS.READY) {
      cachedReadyState = next;
    }
    setState(next);
  };

  useMountEffect(() => {
    if (state.status !== PANEL_CHAT_STATUS.READY) {
      void load();
    }
  });

  if (state.status === PANEL_CHAT_STATUS.LOADING) {
    return <LighthousePanelChatSkeleton />;
  }
  if (state.status === PANEL_CHAT_STATUS.ERROR) {
    return (
      <PanelChatError message={state.message} onRetry={() => void load()} />
    );
  }
  if (state.status === PANEL_CHAT_STATUS.NOT_CONFIGURED) {
    return <PanelChatConnectCta />;
  }
  return (
    <PanelChatReady config={state.config} modelsError={state.modelsError} />
  );
}

interface PanelChatReadyProps {
  config: LighthouseChatConfig;
  modelsError?: string;
}

function PanelChatReady({ config, modelsError }: PanelChatReadyProps) {
  const [store] = useState(() =>
    getOrCreatePanelChatStore(config, { initialError: modelsError }),
  );
  const [sessions, setSessions] = useState<LighthouseV2Session[]>([]);

  const refreshSessions = async () => {
    try {
      const result = await getLighthouseV2Sessions();
      if ("data" in result) {
        setSessions(result.data);
      }
    } catch {
      // Best-effort refresh: swallow transport-level failures so a rejected
      // server action never escapes the mount effect as an unhandled error.
    }
  };

  useMountEffect(() => {
    void refreshSessions();
    const refresh = () => void refreshSessions();
    // Archiving from any surface (sidebar, popover) must reset the panel chat
    // too when its open session is the archived one.
    const handleSessionArchived = (event: Event) => {
      const archivedId = (event as CustomEvent<{ sessionId: string }>).detail
        ?.sessionId;
      if (archivedId) {
        store.getState().handleSessionArchived(archivedId);
      }
    };

    window.addEventListener(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT, refresh);
    window.addEventListener(
      LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
      handleSessionArchived,
    );
    return () => {
      window.removeEventListener(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT, refresh);
      window.removeEventListener(
        LIGHTHOUSE_V2_SESSION_ARCHIVED_EVENT,
        handleSessionArchived,
      );
    };
  });

  return (
    <LighthouseChatStoreProvider store={store}>
      <div className="flex h-full min-h-0 flex-col">
        <div className="min-h-0 flex-1">
          <LighthouseV2ChatView
            surface={LIGHTHOUSE_CHAT_SURFACE.PANEL}
            emptyStateFooter={
              sessions.length > 0 ? (
                <div className="flex max-h-64 flex-col gap-2">
                  <span className="text-text-neutral-secondary text-sm font-medium">
                    Recent chats
                  </span>
                  <PanelChatSessions sessions={sessions} />
                </div>
              ) : undefined
            }
          />
        </div>
      </div>
    </LighthouseChatStoreProvider>
  );
}

interface PanelChatSessionsProps {
  sessions: LighthouseV2Session[];
  onAfterSelect?: () => void;
}

function PanelChatSessions({
  sessions,
  onAfterSelect,
}: PanelChatSessionsProps) {
  const [search, setSearch] = useState("");
  const activeSessionId = useLighthouseChatStore(
    (state) => state.activeSessionId,
  );
  const isOnNewChat = useLighthouseChatStore(
    (state) => state.activeSessionId === null && state.messages.length === 0,
  );
  const openSession = useLighthouseChatStore((state) => state.openSession);
  const resetToNewChat = useLighthouseChatStore(
    (state) => state.resetToNewChat,
  );

  const handleArchiveSession = async (sessionId: string) => {
    try {
      const result = await archiveLighthouseV2Session(sessionId);
      if ("data" in result) {
        // Resets this chat when its open session is archived, and prompts
        // every session list (sidebar included) to refresh.
        notifyLighthouseV2SessionArchived(sessionId);
      }
    } catch {
      // Archiving is recoverable from the list; ignore transient failures.
    }
  };

  return (
    <LighthouseV2SessionHistory
      compact
      sessions={sessions}
      activeSessionId={activeSessionId}
      search={search}
      onSearchChange={setSearch}
      newChatDisabled={isOnNewChat}
      onNewSession={() => {
        resetToNewChat();
        onAfterSelect?.();
      }}
      onOpenSession={(sessionId) => {
        void openSession(sessionId);
        onAfterSelect?.();
      }}
      onArchiveSession={(sessionId) => void handleArchiveSession(sessionId)}
    />
  );
}

interface PanelChatErrorProps {
  message: string;
  onRetry: () => void;
}

function PanelChatError({ message, onRetry }: PanelChatErrorProps) {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
      <p role="alert" className="text-text-neutral-secondary text-sm">
        {message}
      </p>
      <Button type="button" variant="outline" onClick={onRetry}>
        Retry
      </Button>
    </div>
  );
}

function PanelChatConnectCta() {
  return (
    <div className="flex h-full flex-col items-center justify-center gap-4 p-6 text-center">
      <LighthouseIconWithAura className="size-16" />
      <div className="space-y-1">
        <h2 className="text-text-neutral-primary text-base font-semibold">
          Lighthouse AI is not set up yet
        </h2>
        <p className="text-text-neutral-secondary text-sm">
          Connect an LLM provider to start asking questions about your cloud
          security posture.
        </p>
      </div>
      <Button asChild>
        <Link href={LIGHTHOUSE_ROUTE.SETTINGS}>Connect an LLM provider</Link>
      </Button>
    </div>
  );
}

async function loadPanelChatState(): Promise<PanelChatState> {
  try {
    const [configurationsResult, supportedProvidersResult] = await Promise.all([
      getLighthouseV2Configurations(),
      getLighthouseV2SupportedProviders(),
    ]);
    if ("error" in configurationsResult) {
      return {
        status: PANEL_CHAT_STATUS.ERROR,
        message: configurationsResult.error,
      };
    }
    if ("error" in supportedProvidersResult) {
      return {
        status: PANEL_CHAT_STATUS.ERROR,
        message: supportedProvidersResult.error,
      };
    }

    const configurations = configurationsResult.data;
    const hasConnectedProvider = configurations.some(
      (configuration) => configuration.connected === true,
    );
    if (!hasConnectedProvider) {
      return { status: PANEL_CHAT_STATUS.NOT_CONFIGURED };
    }

    const { modelsByProvider, failedModelProviders } =
      await loadLighthouseV2ConnectedModels(
        configurations,
        getLighthouseV2SupportedModels,
      );
    // Surface (rather than silently swallow to []) connected providers whose
    // models failed to load, so their empty list reads as a real backend failure.
    const modelsError =
      failedModelProviders.length > 0
        ? `Could not load available models for: ${failedModelProviders.join(", ")}. Try again shortly.`
        : undefined;

    return {
      status: PANEL_CHAT_STATUS.READY,
      config: {
        configurations,
        modelsByProvider,
        supportedProviders: supportedProvidersResult.data,
      },
      modelsError,
    };
  } catch {
    return {
      status: PANEL_CHAT_STATUS.ERROR,
      message: "Could not load Lighthouse AI. Try again shortly.",
    };
  }
}
