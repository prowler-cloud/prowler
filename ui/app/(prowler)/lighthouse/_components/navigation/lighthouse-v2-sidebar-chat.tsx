"use client";

import { MessageSquare, Plus } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import {
  archiveLighthouseV2Session,
  getLighthouseV2Sessions,
} from "@/app/(prowler)/lighthouse/_actions";
import {
  LIGHTHOUSE_V2_SESSIONS_CHANGED_EVENT,
  notifyLighthouseV2NewChat,
} from "@/app/(prowler)/lighthouse/_lib/session-events";
import type { LighthouseV2Session } from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useMountEffect } from "@/hooks/use-mount-effect";

import { LighthouseV2SessionHistory } from "../history";

export function LighthouseV2SidebarChat({ isOpen }: { isOpen: boolean }) {
  const router = useRouter();
  const searchParams = useSearchParams();
  const activeSessionId = searchParams.get("session");
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
      />
    </div>
  );
}
