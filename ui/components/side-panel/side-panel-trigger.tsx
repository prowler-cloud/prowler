"use client";

import { usePathname } from "next/navigation";

import { LighthouseIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { LIGHTHOUSE_ROUTE } from "@/lib/lighthouse-routes";
import { isCloud } from "@/lib/shared/env";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

export function SidePanelTrigger() {
  const pathname = usePathname();
  const openPanel = useSidePanelStore((state) => state.openPanel);

  // Lighthouse AI (and the panel itself) is cloud-only. On the full-page chat
  // route the panel is not available: the chat lives in one place at a time.
  if (!isCloud()) return null;
  if (pathname?.startsWith(LIGHTHOUSE_ROUTE.CHAT)) return null;

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
