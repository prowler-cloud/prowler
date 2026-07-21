"use client";

import { Maximize2, Plus } from "lucide-react";
import Link from "next/link";
import { useSyncExternalStore } from "react";

import {
  getPanelChatActiveSessionId,
  getPanelChatHasMessages,
  subscribePanelChatHasMessages,
} from "@/app/(prowler)/lighthouse/_lib/panel-chat-message-state";
import { notifyLighthouseV2NewChat } from "@/app/(prowler)/lighthouse/_lib/session-events";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import { cn } from "@/lib/utils";

export function LighthousePanelHeaderActions() {
  const hasMessages = useSyncExternalStore(
    subscribePanelChatHasMessages,
    getPanelChatHasMessages,
    () => false,
  );
  const activeSessionId = useSyncExternalStore(
    subscribePanelChatHasMessages,
    getPanelChatActiveSessionId,
    () => null,
  );
  const fullPageHref = activeSessionId
    ? `${LIGHTHOUSE_ROUTE.CHAT}?session=${encodeURIComponent(activeSessionId)}`
    : LIGHTHOUSE_ROUTE.CHAT;

  return (
    <>
      <Tooltip delayDuration={100}>
        <TooltipTrigger asChild>
          <span
            className={cn("inline-flex", !hasMessages && "cursor-not-allowed")}
          >
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label="New chat"
              disabled={!hasMessages}
              onClick={notifyLighthouseV2NewChat}
            >
              <Plus />
            </Button>
          </span>
        </TooltipTrigger>
        <TooltipContent>
          {hasMessages
            ? "New chat"
            : "Send a message before starting a new chat"}
        </TooltipContent>
      </Tooltip>
      <Tooltip delayDuration={100}>
        <TooltipTrigger asChild>
          <Button asChild variant="ghost" size="icon-sm">
            <Link href={fullPageHref} aria-label="Open Lighthouse AI full page">
              <Maximize2 />
            </Link>
          </Button>
        </TooltipTrigger>
        <TooltipContent>Open full page</TooltipContent>
      </Tooltip>
    </>
  );
}
