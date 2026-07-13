"use client";

import { Plus } from "lucide-react";

import { notifyLighthouseV2NewChat } from "@/app/(prowler)/lighthouse/_lib/session-events";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

export function LighthousePanelHeaderActions() {
  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label="New chat"
          className="ml-auto"
          onClick={notifyLighthouseV2NewChat}
        >
          <Plus />
        </Button>
      </TooltipTrigger>
      <TooltipContent>New chat</TooltipContent>
    </Tooltip>
  );
}
