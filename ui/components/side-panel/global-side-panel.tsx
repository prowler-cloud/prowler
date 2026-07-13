"use client";

import { X } from "lucide-react";
import { usePathname } from "next/navigation";
import { Suspense } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  SidePanel,
  SidePanelBody,
  SidePanelHeader,
  SidePanelResizeHandle,
} from "@/components/shadcn/side-panel/side-panel";
import { useMediaQuery } from "@/hooks/use-media-query";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { isLighthouseChatRoute } from "@/lib/lighthouse-routes";
import {
  clampSidePanelWidth,
  SIDE_PANEL_MAX_WIDTH,
  SIDE_PANEL_MIN_WIDTH,
  SIDE_PANEL_PUSH_MEDIA_QUERY,
} from "@/lib/ui-layout";
import { cn } from "@/lib/utils";
import { SIDE_PANEL_TAB, useSidePanelStore } from "@/store/side-panel";

import { SidePanelErrorBoundary } from "./side-panel-error-boundary";
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
          max={SIDE_PANEL_MAX_WIDTH}
          onResize={handleResize}
          onResizeStart={() => useSidePanelStore.getState().setIsResizing(true)}
          onResizeEnd={() => useSidePanelStore.getState().setIsResizing(false)}
        />
      ) : null}
      <SidePanelHeader>
        {tabCount > 1 ? (
          <div role="tablist" className="flex items-center gap-1">
            {contextTab ? (
              <Button
                type="button"
                role="tab"
                aria-selected={isContextSelected}
                variant={isContextSelected ? "outline" : "ghost"}
                size="sm"
                onClick={() => openPanel(SIDE_PANEL_TAB.CONTEXT)}
              >
                {contextTab.label}
              </Button>
            ) : null}
            {registryTabs.map((tab) => {
              const TabIcon = tab.Icon;
              const isSelected =
                !isContextSelected && tab.id === activeRegistryTab?.id;
              return (
                <Button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={isSelected}
                  variant={isSelected ? "outline" : "ghost"}
                  size="sm"
                  onClick={() => openPanel(tab.id)}
                >
                  <TabIcon className="size-4" />
                  {tab.label}
                </Button>
              );
            })}
          </div>
        ) : (
          <SinglePanelLabel
            contextLabel={contextTab?.label}
            registryTab={activeRegistryTab}
          />
        )}
        {!isContextSelected && activeRegistryTab?.HeaderActions ? (
          <activeRegistryTab.HeaderActions />
        ) : null}
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label="Close side panel"
          className={cn(
            (isContextSelected || !activeRegistryTab?.HeaderActions) &&
              "ml-auto",
          )}
          onClick={() => closePanel()}
        >
          <X />
        </Button>
      </SidePanelHeader>
      {/* Portal target for the registered detail view. Always rendered while
          the panel exists so the owner can portal in as soon as it registers;
          the native hidden attribute keeps it out of the way otherwise. */}
      <SidePanelBody
        ref={(element) =>
          useSidePanelStore.getState().setContextOutlet(element)
        }
        hidden={!isContextSelected}
        data-testid="side-panel-context-outlet"
        className="overflow-hidden p-6 pt-4"
      />
      {/* Registry (AI) content stays mounted after the first open so scroll
          position and composer drafts survive closes. [contain:layout] traps
          streamdown's fixed fullscreen overlay inside the panel. */}
      <SidePanelBody
        hidden={isContextSelected || !activeRegistryTab}
        className="[contain:layout]"
      >
        {hasBeenOpened && activeRegistryTab ? (
          // The boundary keeps a chunk-load rejection inside the panel: this
          // layout-level component sits above every segment error.tsx, so an
          // uncaught error here would replace the whole app via global-error.
          <SidePanelErrorBoundary>
            {/* The fallback is the tab's own 1:1 skeleton, so the moment the
                lazy bundle downloads nothing visually jumps. */}
            <Suspense fallback={<activeRegistryTab.Fallback />}>
              <activeRegistryTab.Content />
            </Suspense>
          </SidePanelErrorBoundary>
        ) : null}
      </SidePanelBody>
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
