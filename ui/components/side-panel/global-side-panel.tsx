"use client";

import { X } from "lucide-react";
import { usePathname } from "next/navigation";

import { Button } from "@/components/shadcn/button/button";
import {
  SidePanel,
  SidePanelBody,
  SidePanelHeader,
  SidePanelResizeHandle,
} from "@/components/shadcn/side-panel/side-panel";
import {
  Tabs,
  TabsContent,
  TabsList,
  TabsTrigger,
} from "@/components/shadcn/tabs/tabs";
import { useMediaQuery } from "@/hooks/use-media-query";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { isLighthouseChatRoute } from "@/lib/lighthouse-routes";
import {
  clampSidePanelWidth,
  getSidePanelMaxWidth,
  SIDE_PANEL_MIN_WIDTH,
  SIDE_PANEL_PUSH_MEDIA_QUERY,
} from "@/lib/ui-layout";
import { cn } from "@/lib/utils";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { RetryableLazyContent } from "./retryable-lazy-content";
import { getVisibleSidePanelTabs } from "./side-panel-tabs";

// Non-modal push panel (PostHog-style): no backdrop, MainLayout shifts the
// page by the panel width so everything stays reachable. It hosts the fixed
// registry tabs (Lighthouse AI, cloud-only) plus one dynamic "context" tab
// that detail views (finding/resource) register and portal their content into
// — one single panel for every right-hand surface. On the full-page chat
// route the panel does not exist at all: the chat lives in one place or the
// other, never both.
export function GlobalSidePanel() {
  const pathname = usePathname();
  const isOpen = useSidePanelStore((state) => state.isOpen);
  const selectedTab = useSidePanelStore((state) => state.selectedTab);
  const hasBeenOpened = useSidePanelStore((state) => state.hasBeenOpened);
  const contextTab = useSidePanelStore((state) => state.contextTab);
  const width = useSidePanelStore((state) => state.width);
  const isResizing = useSidePanelStore((state) => state.isResizing);
  const openPanel = useSidePanelStore((state) => state.openPanel);
  const closePanel = useSidePanelStore((state) => state.closePanel);
  // Stable action for the outlet ref: an inline closure would detach/reattach
  // (null → element) on every render, e.g. on each resize tick.
  const setContextOutlet = useSidePanelStore((state) => state.setContextOutlet);
  // Below `sm` the panel overlays full-width; the resizable px width and the
  // push margin only make sense from `sm` up.
  const isPushViewport = useMediaQuery(SIDE_PANEL_PUSH_MEDIA_QUERY);

  useMountEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Radix overlays (modals, popovers) preventDefault their own Escape.
      if (event.defaultPrevented) return;
      // The full-page chat owns its route: no panel there (read the live URL,
      // the mount closure would keep a stale pathname).
      if (isLighthouseChatRoute(window.location.pathname)) return;
      const store = useSidePanelStore.getState();
      if ((event.metaKey || event.ctrlKey) && event.key === ".") {
        // Nothing to show in OSS without a detail view registered.
        if (getVisibleSidePanelTabs().length === 0 && !store.contextTab) {
          return;
        }
        event.preventDefault();
        store.togglePanel();
        return;
      }
      if (event.key === "Escape" && store.isOpen) {
        store.closePanel();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  });

  const registryTabs = getVisibleSidePanelTabs();
  if (isLighthouseChatRoute(pathname)) return null;
  if (registryTabs.length === 0 && !contextTab) return null;

  // The persisted tab can point at a tab that is not available here; fall
  // back to the context tab first (it was registered on purpose), then to the
  // first registry tab.
  const activeRegistryTab =
    registryTabs.find((tab) => tab.id === selectedTab) ?? registryTabs[0];
  const isContextSelected =
    Boolean(contextTab) &&
    (selectedTab === SIDE_PANEL_TAB.CONTEXT || !activeRegistryTab);
  const tabCount = registryTabs.length + (contextTab ? 1 : 0);
  const activeTabId = isContextSelected
    ? SIDE_PANEL_TAB.CONTEXT
    : activeRegistryTab?.id;

  const handleTabChange = (tabId: string) => {
    if (tabId === SIDE_PANEL_TAB.CONTEXT) {
      openPanel(SIDE_PANEL_TAB.CONTEXT);
      return;
    }
    const registryTab = registryTabs.find((tab) => tab.id === tabId);
    if (registryTab) openPanel(registryTab.id);
  };

  const handleResize = (clientX: number) => {
    // Right-anchored panel: dragging the left edge sets width to the distance
    // between the pointer and the right viewport edge.
    useSidePanelStore.getState().setWidth(window.innerWidth - clientX);
  };

  return (
    <SidePanel
      open={isOpen}
      aria-label="Side panel"
      data-testid="global-side-panel"
      className={cn("w-full", isResizing && "transition-none")}
      // Re-clamp at consumption: a persisted width from a larger monitor
      // rehydrates raw and would otherwise collapse <main> on this viewport.
      style={{ width: isPushViewport ? clampSidePanelWidth(width) : undefined }}
    >
      {isPushViewport ? (
        <SidePanelResizeHandle
          value={width}
          min={SIDE_PANEL_MIN_WIDTH}
          max={getSidePanelMaxWidth()}
          onResize={handleResize}
          onResizeStart={() => useSidePanelStore.getState().setIsResizing(true)}
          onResizeEnd={() => useSidePanelStore.getState().setIsResizing(false)}
        />
      ) : null}
      <Tabs
        value={activeTabId}
        onValueChange={handleTabChange}
        className="flex min-h-0 flex-1 flex-col"
      >
        <SidePanelHeader>
          {tabCount > 1 ? (
            <TabsList>
              {contextTab ? (
                <TabsTrigger value={SIDE_PANEL_TAB.CONTEXT}>
                  {contextTab.label}
                </TabsTrigger>
              ) : null}
              {registryTabs.map((tab) => {
                const TabIcon = tab.Icon;
                return (
                  <TabsTrigger key={tab.id} value={tab.id}>
                    <span className="flex items-center gap-2">
                      <TabIcon />
                      {tab.label}
                    </span>
                  </TabsTrigger>
                );
              })}
            </TabsList>
          ) : (
            <SinglePanelLabel
              contextLabel={contextTab?.label}
              registryTab={activeRegistryTab}
            />
          )}
          <div className="ml-auto flex items-center gap-1">
            {!isContextSelected && activeRegistryTab?.HeaderActions ? (
              <activeRegistryTab.HeaderActions />
            ) : null}
            <Button
              type="button"
              variant="ghost"
              size="icon-sm"
              aria-label="Close side panel"
              onClick={() => closePanel()}
            >
              <X />
            </Button>
          </div>
        </SidePanelHeader>
        {/* Portal target for the registered detail view. Always rendered while
            the panel exists so the owner can portal in as soon as it registers;
            Radix keeps the inactive panel mounted but hidden. */}
        <TabsContent
          value={SIDE_PANEL_TAB.CONTEXT}
          className="relative mt-0 min-h-0 flex-1 data-[state=inactive]:hidden"
          forceMount
          asChild
        >
          <SidePanelBody
            hidden={!isContextSelected}
            className="overflow-hidden p-6 pt-4"
          >
            {/* Plain inner node: the outlet ref must not go through Radix's
                Slot (asChild), whose per-render composeRefs would detach and
                reattach it — flickering the store outlet — on every render. */}
            <div
              ref={setContextOutlet}
              data-testid="side-panel-context-outlet"
              className="h-full"
            />
          </SidePanelBody>
        </TabsContent>
        {/* Registry (AI) content stays mounted after the first open so scroll
            position and composer drafts survive closes. [contain:layout] traps
            streamdown's fixed fullscreen overlay inside the panel. */}
        {activeRegistryTab ? (
          <TabsContent
            value={activeRegistryTab.id}
            className="relative mt-0 min-h-0 flex-1 data-[state=inactive]:hidden"
            forceMount
            asChild
          >
            <SidePanelBody
              hidden={isContextSelected}
              className="[contain:layout]"
            >
              {hasBeenOpened ? (
                // key: a tab switch must reset the lazy instance and any
                // error-boundary state from the previous tab.
                <RetryableLazyContent
                  key={activeRegistryTab.id}
                  load={activeRegistryTab.loadContent}
                  fallback={<activeRegistryTab.Fallback />}
                />
              ) : null}
            </SidePanelBody>
          </TabsContent>
        ) : null}
      </Tabs>
    </SidePanel>
  );
}

interface SinglePanelLabelProps {
  contextLabel?: string;
  registryTab?: ReturnType<typeof getVisibleSidePanelTabs>[number];
}

function SinglePanelLabel({
  contextLabel,
  registryTab,
}: SinglePanelLabelProps) {
  if (contextLabel) {
    return (
      <div className="text-text-neutral-primary flex items-center gap-2 text-sm font-medium">
        {contextLabel}
      </div>
    );
  }
  if (!registryTab) return null;
  const Icon = registryTab.Icon;
  return (
    <div className="text-text-neutral-primary flex items-center gap-2 text-sm font-medium">
      <Icon className="size-4" />
      {registryTab.label}
    </div>
  );
}
