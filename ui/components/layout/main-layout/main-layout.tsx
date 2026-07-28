"use client";

import { usePathname } from "next/navigation";
import { type ReactNode, Suspense } from "react";

import { JiraDispatchModalHost } from "@/components/findings/jira-dispatch-modal-host";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { CloudUpgradeModal } from "@/components/shared/cloud-upgrade-modal";
import { useMediaQuery } from "@/hooks/use-media-query";
import { useStore } from "@/hooks/use-store";
import { isLighthouseChatRoute } from "@/lib/lighthouse-routes";
import {
  clampSidePanelWidth,
  SIDE_PANEL_PUSH_MEDIA_QUERY,
} from "@/lib/ui-layout";
import { cn } from "@/lib/utils";
import { useSidePanelStore } from "@/store/side-panel";

export default function MainLayout({ children }: { children: ReactNode }) {
  const pathname = usePathname();
  // Push (not overlay): the open side panel shrinks the page by exactly its
  // (user-resizable) width so everything stays reachable. Below `sm` the
  // panel overlays full-width instead, where pushing would leave no page. The
  // full-page chat route has no panel at all.
  const sidePanelOpen = useStore(useSidePanelStore, (x) => x.isOpen);
  const sidePanelWidth = useStore(useSidePanelStore, (x) => x.width);
  const sidePanelResizing = useStore(useSidePanelStore, (x) => x.isResizing);
  const isPushViewport = useMediaQuery(SIDE_PANEL_PUSH_MEDIA_QUERY);
  // Re-clamp at consumption: a persisted width from a larger monitor
  // rehydrates raw and would otherwise collapse <main> on this viewport.
  const pushWidth =
    sidePanelOpen &&
    sidePanelWidth !== undefined &&
    isPushViewport &&
    !isLighthouseChatRoute(pathname)
      ? clampSidePanelWidth(sidePanelWidth)
      : undefined;
  return (
    <div className="relative flex h-dvh items-center justify-center overflow-hidden">
      <AppSidebar />
      <CloudUpgradeModal />
      <JiraDispatchModalHost />
      <main
        // @container: <main> is the reference for the app's (container-query)
        // breakpoints, so pushing it with the side panel re-evaluates them.
        // min-[64rem] (not lg:) keeps the sidebar margin on viewport terms.
        // The 16px gutter is padding (not margin): main scrolls, and a scroll
        // container clips at its padding box — the navbar's border-b bleeds
        // across this gutter to meet the sidebar's border-r.
        data-responsive-container
        className={cn(
          "no-scrollbar @container relative z-10 mb-auto h-full flex-1 flex-col overflow-y-auto pl-4 min-[64rem]:ml-[264px]",
          // Margin animates on open/close, but tracks the pointer 1:1 during
          // a drag resize.
          !sidePanelResizing &&
            "transition-[margin-left,margin-right] duration-300 ease-in-out",
        )}
        style={{ marginRight: pushWidth }}
      >
        <Suspense fallback={null}>{children}</Suspense>
      </main>
    </div>
  );
}
