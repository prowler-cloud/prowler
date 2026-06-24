"use client";

import { Archive, MessageSquare, Plus } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import { SearchInput } from "@/components/shadcn/search-input/search-input";
import { cn } from "@/lib/utils";
import type { LighthouseV2Session } from "@/types/lighthouse-v2";

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
  const groups = groupSessionsByDate(sessions);

  return (
    <aside className={cn("flex min-h-0 flex-col gap-3", compact && "gap-2")}>
      <div className="flex items-center gap-2">
        <SearchInput
          aria-label="Search Lighthouse sessions"
          value={search}
          placeholder="Search chats"
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

      <div className="minimal-scrollbar min-h-0 flex-1 overflow-y-auto">
        {groups.length === 0 ? (
          <div className="text-text-neutral-secondary px-2 py-8 text-center text-sm">
            No chats
          </div>
        ) : (
          <div className="flex flex-col gap-4">
            {groups.map((group) => (
              <section key={group.label} className="grid gap-1">
                <h3 className="text-text-neutral-tertiary px-2 text-xs font-medium">
                  {group.label}
                </h3>
                {group.sessions.map((session) => (
                  <div
                    key={session.id}
                    className={cn(
                      "group flex items-center gap-1 rounded-[8px]",
                      activeSessionId === session.id &&
                        "bg-bg-neutral-tertiary",
                    )}
                  >
                    <button
                      type="button"
                      className="hover:bg-bg-neutral-tertiary flex min-w-0 flex-1 items-center gap-2 rounded-[8px] px-2 py-2 text-left text-sm"
                      onClick={() => onOpenSession(session.id)}
                    >
                      <MessageSquare className="text-text-neutral-tertiary size-4 shrink-0" />
                      <span className="truncate">
                        {session.title || "Untitled chat"}
                      </span>
                    </button>
                    <Button
                      type="button"
                      aria-label={`Archive ${session.title || "chat"}`}
                      variant="bare"
                      size="icon-xs"
                      className="mr-1 opacity-0 transition-opacity group-hover:opacity-100 focus-visible:opacity-100"
                      onClick={() => onArchiveSession(session.id)}
                    >
                      <Archive />
                    </Button>
                  </div>
                ))}
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
  const formatter = new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
  const groups = new Map<string, LighthouseV2Session[]>();

  sessions.forEach((session) => {
    const label = formatter.format(new Date(session.updatedAt));
    groups.set(label, [...(groups.get(label) ?? []), session]);
  });

  return Array.from(groups.entries()).map(([label, groupSessions]) => ({
    label,
    sessions: groupSessions,
  }));
}
