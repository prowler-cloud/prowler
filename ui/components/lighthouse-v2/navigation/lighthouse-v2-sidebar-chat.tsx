"use client";

import { MessageSquare, Plus } from "lucide-react";
import { useRouter } from "next/navigation";
import { useState } from "react";

import {
  archiveLighthouseV2Session,
  getLighthouseV2Sessions,
} from "@/actions/lighthouse-v2/lighthouse-v2";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useMountEffect } from "@/hooks/use-mount-effect";
import type { LighthouseV2Session } from "@/types/lighthouse-v2";

import { LighthouseV2SessionHistory } from "../history";

export function LighthouseV2SidebarChat({ isOpen }: { isOpen: boolean }) {
  const router = useRouter();
  const [sessions, setSessions] = useState<LighthouseV2Session[]>([]);
  const [search, setSearch] = useState("");

  const refreshSessions = async (nextSearch = search) => {
    const result = await getLighthouseV2Sessions(
      nextSearch ? { search: nextSearch } : undefined,
    );
    if ("data" in result) {
      setSessions(result.data);
    }
  };

  const handleSearchChange = (value: string) => {
    setSearch(value);
    void refreshSessions(value);
  };

  const handleNewSession = () => {
    router.push("/lighthouse");
  };

  const handleOpenSession = (sessionId: string) => {
    router.push(`/lighthouse?session=${encodeURIComponent(sessionId)}`);
  };

  const handleArchiveSession = async (sessionId: string) => {
    const result = await archiveLighthouseV2Session(sessionId);
    if ("data" in result) {
      setSessions((current) =>
        current.filter((session) => session.id !== sessionId),
      );
    }
  };

  useMountEffect(() => {
    void refreshSessions();
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
        search={search}
        onSearchChange={handleSearchChange}
        onNewSession={handleNewSession}
        onOpenSession={handleOpenSession}
        onArchiveSession={handleArchiveSession}
      />
    </div>
  );
}
