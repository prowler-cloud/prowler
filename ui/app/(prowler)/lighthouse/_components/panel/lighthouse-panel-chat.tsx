"use client";

import Link from "next/link";
import { useState } from "react";

import {
  archiveLighthouseV2Session,
  getLighthouseV2Sessions,
} from "@/app/(prowler)/lighthouse/_actions";
import { LighthouseV2SessionHistory } from "@/app/(prowler)/lighthouse/_components/history";
import type { LighthouseChatConfig } from "@/app/(prowler)/lighthouse/_lib/chat-store";
import {
  LIGHTHOUSE_CHAT_CONFIG_STATUS,
  loadLighthouseChatConfig,
} from "@/app/(prowler)/lighthouse/_lib/load-chat-config";
import {
  getOrCreatePanelChatStore,
  resetPanelChatStore,
} from "@/app/(prowler)/lighthouse/_lib/panel-chat-store";
import {
  notifyLighthouseV2SessionArchived,
  onLighthouseV2ConfigurationsChanged,
  onLighthouseV2SessionArchived,
  onLighthouseV2SessionsChanged,
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

// Config CRUD happens on the settings route, where the global panel (and this
// component) is unmounted — invalidate at module scope so the next open
// rebuilds cache and store against the new configuration.
if (typeof window !== "undefined") {
  onLighthouseV2ConfigurationsChanged(() => {
    cachedReadyState = null;
    resetPanelChatStore();
  });
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
    // The module-scope listener above already invalidated cache and store
    // (registration order); reload so an open panel refreshes in place.
    return onLighthouseV2ConfigurationsChanged(() => void load());
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
    const unsubscribeSessionsChanged = onLighthouseV2SessionsChanged(() => {
      void refreshSessions();
    });
    // Archiving from any surface (sidebar, popover) must reset the panel chat
    // when its open session is the archived one, and drop the archived chat
    // from the "Recent chats" list.
    const unsubscribeSessionArchived = onLighthouseV2SessionArchived(
      (sessionId) => {
        store.getState().handleSessionArchived(sessionId);
        void refreshSessions();
      },
    );
    return () => {
      unsubscribeSessionsChanged();
      unsubscribeSessionArchived();
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
    const result = await loadLighthouseChatConfig();
    if (result.status === LIGHTHOUSE_CHAT_CONFIG_STATUS.ERROR) {
      return { status: PANEL_CHAT_STATUS.ERROR, message: result.message };
    }
    if (result.status === LIGHTHOUSE_CHAT_CONFIG_STATUS.NOT_CONFIGURED) {
      return { status: PANEL_CHAT_STATUS.NOT_CONFIGURED };
    }
    return {
      status: PANEL_CHAT_STATUS.READY,
      config: result.config,
      modelsError: result.modelsError,
    };
  } catch {
    return {
      status: PANEL_CHAT_STATUS.ERROR,
      message: "Could not load Lighthouse AI. Try again shortly.",
    };
  }
}
