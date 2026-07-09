"use client";

import { Archive, Plus } from "lucide-react";
import { useState } from "react";

import { formatSessionAge } from "@/app/(prowler)/lighthouse/_lib/format";
import type { LighthouseV2Session } from "@/app/(prowler)/lighthouse/_types";
import { Button } from "@/components/shadcn/button/button";
import { Modal } from "@/components/shadcn/modal";
import { SearchInput } from "@/components/shadcn/search-input/search-input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

interface LighthouseV2SessionHistoryProps {
  sessions: LighthouseV2Session[];
  activeSessionId?: string | null;
  search: string;
  onSearchChange: (value: string) => void;
  onNewSession: () => void;
  onOpenSession: (sessionId: string) => void;
  onArchiveSession: (sessionId: string) => void;
  newChatDisabled?: boolean;
  compact?: boolean;
}

export function LighthouseV2SessionHistory({
  sessions,
  activeSessionId,
  search,
  onSearchChange,
  onNewSession,
  onOpenSession,
  onArchiveSession,
  newChatDisabled = false,
  compact = false,
}: LighthouseV2SessionHistoryProps) {
  const [sessionPendingArchive, setSessionPendingArchive] =
    useState<LighthouseV2Session | null>(null);
  const visibleSessions = filterSessionsBySearch(sessions, search);

  const handleArchiveModalOpenChange = (open: boolean) => {
    if (!open) {
      setSessionPendingArchive(null);
    }
  };

  const handleConfirmArchive = () => {
    if (!sessionPendingArchive) return;

    onArchiveSession(sessionPendingArchive.id);
    setSessionPendingArchive(null);
  };

  return (
    <aside
      className={cn(
        "flex min-h-0 w-full min-w-0 flex-col gap-3 overflow-hidden",
        compact && "gap-2",
      )}
    >
      <div className="flex items-center gap-2">
        <SearchInput
          aria-label="Search Lighthouse AI sessions"
          value={search}
          placeholder="Chat history"
          size={compact ? "sm" : "default"}
          onChange={(event) => onSearchChange(event.target.value)}
          onClear={() => onSearchChange("")}
        />
        <Tooltip delayDuration={100}>
          <TooltipTrigger asChild>
            <Button
              type="button"
              aria-label="New chat"
              size={compact ? "icon-sm" : "icon"}
              disabled={newChatDisabled}
              onClick={onNewSession}
            >
              <Plus />
            </Button>
          </TooltipTrigger>
          <TooltipContent side="right">New chat</TooltipContent>
        </Tooltip>
      </div>

      <div className="minimal-scrollbar min-h-0 min-w-0 flex-1 overflow-x-hidden overflow-y-auto">
        {visibleSessions.length === 0 ? (
          <div className="text-text-neutral-secondary px-2 py-8 text-center text-sm">
            No chats
          </div>
        ) : (
          <div className="grid min-w-0">
            {visibleSessions.map((session) => {
              const sessionTitle = session.title || "Untitled chat";
              const isActive = activeSessionId === session.id;

              return (
                <div
                  key={session.id}
                  className={cn(
                    "hover:bg-bg-neutral-tertiary group relative flex min-w-0 items-center overflow-hidden rounded-[8px] transition-colors",
                    isActive &&
                      "bg-bg-neutral-tertiary before:bg-button-primary before:absolute before:top-1/2 before:left-0 before:h-5 before:w-0.5 before:-translate-y-1/2 before:rounded-full",
                  )}
                >
                  <Tooltip delayDuration={100}>
                    <TooltipTrigger asChild>
                      <button
                        type="button"
                        className={cn(
                          "flex min-w-0 flex-1 items-center gap-2 overflow-hidden rounded-[8px] px-2 py-2 text-left text-sm",
                          isActive && "text-text-neutral-primary",
                        )}
                        onClick={() => onOpenSession(session.id)}
                      >
                        <span
                          className={cn(
                            "min-w-0 flex-1 truncate",
                            isActive && "font-medium",
                          )}
                        >
                          {sessionTitle}
                        </span>
                        <span className="text-text-neutral-tertiary min-w-[3.25rem] shrink-0 text-right text-xs whitespace-nowrap transition-opacity group-focus-within:opacity-0 group-hover:opacity-0">
                          {formatSessionAge(session.updatedAt)}
                        </span>
                      </button>
                    </TooltipTrigger>
                    <TooltipContent side="right">{sessionTitle}</TooltipContent>
                  </Tooltip>
                  <Button
                    type="button"
                    aria-label={`Archive ${sessionTitle}`}
                    variant="bare"
                    size="icon-xs"
                    className="hover:text-text-neutral-secondary active:text-text-neutral-secondary absolute top-1/2 right-1 -translate-y-1/2 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100 focus-visible:opacity-100"
                    onClick={() => setSessionPendingArchive(session)}
                  >
                    <Archive />
                  </Button>
                </div>
              );
            })}
          </div>
        )}
      </div>

      <Modal
        open={Boolean(sessionPendingArchive)}
        onOpenChange={handleArchiveModalOpenChange}
        title="Are you absolutely sure?"
        description="This action cannot be undone. This will archive this chat and remove it from your chat history."
        size="md"
      >
        <div className="flex w-full justify-end gap-4">
          <Button
            type="button"
            variant="ghost"
            size="lg"
            onClick={() => setSessionPendingArchive(null)}
          >
            Cancel
          </Button>
          <Button
            type="button"
            variant="destructive"
            size="lg"
            onClick={handleConfirmArchive}
          >
            <Archive />
            Archive
          </Button>
        </div>
      </Modal>
    </aside>
  );
}

function filterSessionsBySearch(
  sessions: LighthouseV2Session[],
  search: string,
): LighthouseV2Session[] {
  const normalizedSearch = search.trim().toLocaleLowerCase();
  if (!normalizedSearch) return sessions;

  return sessions.filter((session) =>
    (session.title || "Untitled chat")
      .toLocaleLowerCase()
      .includes(normalizedSearch),
  );
}
