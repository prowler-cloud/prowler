"use client";

import { LighthouseIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { isCloud } from "@/lib/shared/env";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

export function SidePanelTrigger() {
  const openPanel = useSidePanelStore((state) => state.openPanel);

  // Lighthouse AI (and the panel itself) is cloud-only.
  if (!isCloud()) return null;

  return (
    <Tooltip delayDuration={100}>
      <TooltipTrigger asChild>
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label="Ask Lighthouse AI"
          data-testid="side-panel-ai-trigger"
          onClick={() => openPanel(SIDE_PANEL_TAB.AI_CHAT)}
        >
          <LighthouseIcon className="size-5" />
        </Button>
      </TooltipTrigger>
      <TooltipContent>
        Ask Lighthouse AI <kbd className="ml-1 text-xs">⌘.</kbd>
      </TooltipContent>
    </Tooltip>
  );
}
