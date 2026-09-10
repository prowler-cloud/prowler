"use client";

import { MessageSquare, Plus } from "lucide-react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { useState, useSyncExternalStore } from "react";

import {
  archiveLighthouseV2Session,
  getLighthouseV2Sessions,
} from "@/app/(prowler)/lighthouse/_actions";
import {
  LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT,
  notifyLighthouseV2NewChat,
  notifyLighthouseV2SessionArchived,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import type { LighthouseV2Session } from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";

import { LighthouseV2SessionHistory } from "../history";

export function LighthouseV2SidebarChat({ isOpen }: { isOpen: boolean }) {
  const router = useRouter();
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const activeSessionId = searchParams.get("session");
  const browserUrlSessionId = useBrowserUrlSessionId();
  // A pristine new chat is the chat route with no session anywhere; there,
  // starting yet another new chat is a no-op.
  const isOnNewChat =
    pathname === LIGHTHOUSE_ROUTE.CHAT &&
    !activeSessionId &&
    !browserUrlSessionId;
  const [sessions, setSessions] = useState<LighthouseV2Session[]>([]);
  const [search, setSearch] = useState("");

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

  const handleSearchChange = (value: string) => {
    setSearch(value);
  };

  const handleNewSession = () => {
    // Reset an already-open chat in place, then route (covers other pages too).
    notifyLighthouseV2NewChat();
    router.push("/lighthouse");
  };

  const handleOpenSession = (sessionId: string) => {
    router.push(`/lighthouse?session=${encodeURIComponent(sessionId)}`);
  };

  const handleArchiveSession = async (sessionId: string) => {
    try {
      const result = await archiveLighthouseV2Session(sessionId);
      if ("data" in result) {
        setSessions((current) =>
          current.filter((session) => session.id !== sessionId),
        );
        // Covers live-created sessions the router can't see (replaceState URL).
        notifyLighthouseV2SessionArchived(sessionId);
        if (sessionId === activeSessionId) {
          // The archived session no longer exists; leave its URL.
          router.push("/lighthouse");
        }
      }
    } catch {
      // Archiving is recoverable from the sidebar; ignore transient failures.
    }
  };

  useMountEffect(() => {
    void refreshSessions();
    const refresh = () => void refreshSessions();
    window.addEventListener(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT, refresh);
    return () => {
      window.removeEventListener(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT, refresh);
    };
  });

  if (!isOpen) {
    return (
      <div className="flex flex-col items-center gap-2 px-2 pt-4">
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <Button
              type="button"
              aria-label="New chat"
              size="icon"
              disabled={isOnNewChat}
              onClick={handleNewSession}
            >
              <Plus />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="right">New chat</TooltipContent>
        </Tooltip>
        <MessageSquare className="text-text-neutral-tertiary size-5" />
      </div>
    );
  }

  return (
    <div className="flex h-full min-h-0 flex-col px-2 pt-4">
      <LighthouseV2SessionHistory
        compact
        sessions={sessions}
        activeSessionId={activeSessionId}
        search={search}
        onSearchChange={handleSearchChange}
        onNewSession={handleNewSession}
        onOpenSession={handleOpenSession}
        onArchiveSession={handleArchiveSession}
        newChatDisabled={isOnNewChat}
      />
    </div>
  );
}

// Sessions created live set their URL via replaceState, invisible to Next's
// router, so the real browser URL is the only reliable session source.
function useBrowserUrlSessionId() {
  return useSyncExternalStore(
    subscribeToSessionUrl,
    readBrowserUrlSessionId,
    () => null,
  );
}

function subscribeToSessionUrl(onChange: () => void) {
  window.addEventListener(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT, onChange);
  window.addEventListener("popstate", onChange);
  return () => {
    window.removeEventListener(LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT, onChange);
    window.removeEventListener("popstate", onChange);
  };
}

function readBrowserUrlSessionId() {
  return new URLSearchParams(window.location.search).get("session");
}
