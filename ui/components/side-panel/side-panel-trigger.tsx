"use client";

import { usePathname } from "next/navigation";
import { useState } from "react";

import { LighthouseIcon } from "@/components/icons";
import { Button } from "@/components/shadcn/button/button";
import {
  DiscoveryCallout,
  DiscoveryCalloutAnchor,
  DiscoveryCalloutContent,
} from "@/components/shadcn/discovery-callout/discovery-callout";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { isLighthouseChatRoute } from "@/lib/lighthouse-routes";
import { isCloud } from "@/lib/shared/env";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

// Late enough that the page has settled and the callout reads as a pointer,
// not as part of the page loading in.
const AI_HINT_DELAY_MS = 1500;

export function SidePanelTrigger() {
  const pathname = usePathname();
  const openPanel = useSidePanelStore((state) => state.openPanel);
  // Hidden while the AI chat is already showing; kept while the panel shows a
  // detail (context) tab, where the trigger is the way back to the chat.
  const isAiChatPanelOpen = useSidePanelStore(
    (state) => state.isOpen && state.selectedTab === SIDE_PANEL_TAB.AI_CHAT,
  );
  // One-time discovery callout: opens once after a short delay and never
  // again — dismissing it or reaching the AI chat any other way (⌘., the
  // Overview banner) marks it seen in the persisted store.
  const hintSeen = useSidePanelStore((state) => state.hasSeenAiTriggerHint);
  const markHintSeen = useSidePanelStore(
    (state) => state.markAiTriggerHintSeen,
  );
  const [hintReady, setHintReady] = useState(false);

  useMountEffect(() => {
    if (useSidePanelStore.getState().hasSeenAiTriggerHint) return;
    const timer = setTimeout(() => setHintReady(true), AI_HINT_DELAY_MS);
    return () => clearTimeout(timer);
  });

  // Lighthouse AI (and the panel itself) is cloud-only. On the full-page chat
  // route the panel is not available: the chat lives in one place at a time.
  if (!isCloud()) return null;
  if (isLighthouseChatRoute(pathname)) return null;
  if (isAiChatPanelOpen) return null;

  // Gated on hintReady (client-only) so SSR and hydration render the calm
  // icon; the glow starts with the callout and stops once discovered.
  const undiscovered = hintReady && !hintSeen;

  return (
    <DiscoveryCallout open={undiscovered} onDismiss={markHintSeen}>
      <Tooltip delayDuration={100}>
        <TooltipTrigger asChild>
          <DiscoveryCalloutAnchor asChild>
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label="Ask Lighthouse AI"
              data-testid="side-panel-ai-trigger"
              onClick={() => openPanel(SIDE_PANEL_TAB.AI_CHAT)}
            >
              <LighthouseIcon animatedAura={undiscovered} className="size-5" />
            </Button>
          </DiscoveryCalloutAnchor>
        </TooltipTrigger>
        <TooltipContent>
          Ask Lighthouse AI <kbd className="ml-1 text-xs">⌘.</kbd>
        </TooltipContent>
      </Tooltip>
      <DiscoveryCalloutContent
        title="Ask Lighthouse AI from any page"
        description={
          <>
            Open the assistant right here whenever you need it, or press{" "}
            <kbd className="text-xs">⌘.</kbd> to toggle it.
          </>
        }
        data-testid="side-panel-ai-hint"
      />
    </DiscoveryCallout>
  );
}
