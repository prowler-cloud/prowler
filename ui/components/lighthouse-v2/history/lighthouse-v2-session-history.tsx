"use client";

import { Archive, Plus } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import { SearchInput } from "@/components/shadcn/search-input/search-input";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";
import type { LighthouseV2Session } from "@/types/lighthouse-v2";

const SESSION_HISTORY_GROUP_LABEL = "Older";

interface LighthouseV2SessionHistoryProps {
  sessions: LighthouseV2Session[];
  activeSessionId?: string | null;
  search: string;
  onSearchChange: (value: string) => void;
  onNewSession: () => void;
  onOpenSession: (sessionId: string) => void;
  onArchiveSession: (sessionId: string) => void;
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
  compact = false,
}: LighthouseV2SessionHistoryProps) {
  const visibleSessions = filterSessionsBySearch(sessions, search);
  const groups = groupSessionsByDate(visibleSessions);

  return (
    <aside
      className={cn(
        "flex min-h-0 w-full min-w-0 flex-col gap-3 overflow-hidden",
        compact && "gap-2",
      )}
    >
      <div className="flex items-center gap-2">
        <SearchInput
          aria-label="Search Lighthouse sessions"
          value={search}
          placeholder="Chat history"
          size={compact ? "sm" : "default"}
          onChange={(event) => onSearchChange(event.target.value)}
          onClear={() => onSearchChange("")}
        />
        <Button
          type="button"
          aria-label="New chat"
          size={compact ? "icon-sm" : "icon"}
          onClick={onNewSession}
        >
          <Plus />
        </Button>
      </div>

      <div className="minimal-scrollbar min-h-0 min-w-0 flex-1 overflow-x-hidden overflow-y-auto">
        {groups.length === 0 ? (
          <div className="text-text-neutral-secondary px-2 py-8 text-center text-sm">
            No chats
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {groups.map((group) => (
              <section key={group.label} className="grid min-w-0">
                <h3 className="text-text-neutral-tertiary px-2 py-1 text-xs font-semibold tracking-wide uppercase">
                  {group.label}
                </h3>
                {group.sessions.map((session) => {
                  const sessionTitle = session.title || "Untitled chat";

                  return (
                    <div
                      key={session.id}
                      className={cn(
                        "hover:bg-bg-neutral-tertiary group relative flex min-w-0 items-center overflow-hidden rounded-[8px] transition-colors",
                        activeSessionId === session.id &&
                          "bg-bg-neutral-tertiary",
                      )}
                    >
                      <Tooltip delayDuration={100}>
                        <TooltipTrigger asChild>
                          <button
                            type="button"
                            className="flex min-w-0 flex-1 items-center gap-2 overflow-hidden rounded-[8px] px-2 py-2 text-left text-sm"
                            onClick={() => onOpenSession(session.id)}
                          >
                            <span className="min-w-0 flex-1 truncate">
                              {sessionTitle}
                            </span>
                            <span className="text-text-neutral-tertiary min-w-[3.25rem] shrink-0 text-right text-xs whitespace-nowrap transition-opacity group-focus-within:opacity-0 group-hover:opacity-0">
                              {formatAgeLabel(session.updatedAt)}
                            </span>
                          </button>
                        </TooltipTrigger>
                        <TooltipContent side="right">
                          {sessionTitle}
                        </TooltipContent>
                      </Tooltip>
                      <Button
                        type="button"
                        aria-label={`Archive ${sessionTitle}`}
                        variant="bare"
                        size="icon-xs"
                        className="hover:text-text-neutral-secondary active:text-text-neutral-secondary absolute top-1/2 right-1 -translate-y-1/2 opacity-0 transition-opacity group-focus-within:opacity-100 group-hover:opacity-100 focus-visible:opacity-100"
                        onClick={() => onArchiveSession(session.id)}
                      >
                        <Archive />
                      </Button>
                    </div>
                  );
                })}
              </section>
            ))}
          </div>
        )}
      </div>
    </aside>
  );
}

interface SessionGroup {
  label: string;
  sessions: LighthouseV2Session[];
}

function groupSessionsByDate(sessions: LighthouseV2Session[]): SessionGroup[] {
  if (sessions.length === 0) return [];

  return [
    {
      label: SESSION_HISTORY_GROUP_LABEL,
      sessions,
    },
  ];
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

function formatAgeLabel(dateString: string) {
  const ageInDays = getAgeInDays(dateString);
  if (ageInDays === 0) return "Today";

  return ageInDays === 1 ? "1 day" : `${ageInDays} days`;
}

function getAgeInDays(dateString: string) {
  const date = new Date(dateString);
  const now = new Date();
  const startOfDate = new Date(
    date.getFullYear(),
    date.getMonth(),
    date.getDate(),
  );
  const startOfToday = new Date(
    now.getFullYear(),
    now.getMonth(),
    now.getDate(),
  );
  const millisecondsPerDay = 24 * 60 * 60 * 1000;
  return Math.max(
    0,
    Math.floor(
      (startOfToday.getTime() - startOfDate.getTime()) / millisecondsPerDay,
    ),
  );
}
