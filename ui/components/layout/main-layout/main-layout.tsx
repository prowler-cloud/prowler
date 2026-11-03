"use client";

import { type ReactNode, Suspense } from "react";

import { JiraDispatchModalHost } from "@/components/findings/jira-dispatch-modal-host";
import { RecheckResourceModalHost } from "@/components/findings/recheck-resource-modal-host";
import { AppSidebar } from "@/components/layout/app-sidebar";
import { useSidePanelPushWidth } from "@/hooks/use-side-panel-push-width";
import { useStore } from "@/hooks/use-store";
import { cn } from "@/lib/utils";
import { selectHasModalHost, useSidePanelStore } from "@/store/side-panel";

export default function MainLayout({ children }: { children: ReactNode }) {
  // Push (not overlay): the open side panel shrinks the page by exactly its
  // (user-resizable) width so everything stays reachable. Below `sm` the
  // panel overlays full-width instead, where pushing would leave no page. The
  // full-page chat route has no panel at all.
  const pushWidth = useSidePanelPushWidth();
  const sidePanelResizing = useStore(useSidePanelStore, (x) => x.isResizing);
  // A non-modal dialog sharing the screen with the panel covers the shell, so
  // the shell leaves the tab order and the accessibility tree meanwhile.
  const isShellInert = useSidePanelStore(selectHasModalHost);
  return (
    // Cloudy "framed sheet": the sidebar sits on the tinted frame; the page is a
    // white sheet inset 8px from the window edges, 1px edge, 16px corners, no shadow.
    <div className="bg-bg-neutral-primary relative flex h-dvh items-center justify-center overflow-hidden min-[64rem]:py-2 min-[64rem]:pr-2">
      <AppSidebar inert={isShellInert} />
      <JiraDispatchModalHost />
      <RecheckResourceModalHost />
      <main
        // @container: <main> is the reference for the app's (container-query)
        // breakpoints, so pushing it with the side panel re-evaluates them.
        // min-[64rem] (not lg:) keeps the sidebar margin on viewport terms.
        // The 16px gutter is padding (not margin): main scrolls, and a scroll
        // container clips at its padding box — the navbar's border-b bleeds
        // across this gutter to meet the sidebar's border-r.
        data-responsive-container
        inert={isShellInert}
        className={cn(
          "no-scrollbar @container bg-bg-neutral-secondary relative z-10 mb-auto h-full flex-1 flex-col overflow-y-auto pl-4 min-[64rem]:ml-[248px] min-[64rem]:rounded-2xl min-[64rem]:border min-[64rem]:border-border-neutral-secondary",
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
