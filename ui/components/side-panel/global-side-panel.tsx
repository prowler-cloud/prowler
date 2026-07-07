"use client";

import { X } from "lucide-react";
import { Suspense } from "react";

import { Button } from "@/components/shadcn/button/button";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { cn } from "@/lib/utils";
import { useSidePanelStore } from "@/store/side-panel";

import { getVisibleSidePanelTabs } from "./side-panel-tabs";

// Non-modal overlay panel (PostHog-style): no backdrop, the page stays
// interactive while it is open. z-40 is deliberately below vaul's z-50 so the
// Findings/Resources detail drawers stack over it.
export function GlobalSidePanel() {
  const isOpen = useSidePanelStore((state) => state.isOpen);
  const selectedTab = useSidePanelStore((state) => state.selectedTab);
  const hasBeenOpened = useSidePanelStore((state) => state.hasBeenOpened);
  const openPanel = useSidePanelStore((state) => state.openPanel);
  const closePanel = useSidePanelStore((state) => state.closePanel);

  useMountEffect(() => {
    const handleKeyDown = (event: KeyboardEvent) => {
      // Radix overlays (modals, popovers) preventDefault their own Escape.
      if (event.defaultPrevented) return;
      if ((event.metaKey || event.ctrlKey) && event.key === ".") {
        event.preventDefault();
        useSidePanelStore.getState().togglePanel();
        return;
      }
      if (event.key === "Escape" && useSidePanelStore.getState().isOpen) {
        useSidePanelStore.getState().closePanel();
      }
    };

    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  });

  const visibleTabs = getVisibleSidePanelTabs();
  if (visibleTabs.length === 0) return null;

  // The persisted tab can point at a tab that is not available in this
  // deployment; fall back to the first visible one.
  const activeTab =
    visibleTabs.find((tab) => tab.id === selectedTab) ?? visibleTabs[0];
  const ActiveIcon = activeTab.Icon;
  const ActiveContent = activeTab.Content;

  return (
    <aside
      role="complementary"
      aria-label="Side panel"
      data-testid="global-side-panel"
      inert={!isOpen}
      className={cn(
        "border-border-neutral-secondary bg-bg-neutral-secondary fixed inset-y-0 right-0 z-40 flex w-full flex-col border-l shadow-xl transition-transform duration-200 sm:w-[420px] xl:w-[480px]",
        isOpen ? "translate-x-0" : "translate-x-full",
      )}
    >
      <div className="border-border-neutral-secondary flex items-center gap-1 border-b px-3 py-2">
        {visibleTabs.length > 1 ? (
          <div role="tablist" className="flex items-center gap-1">
            {visibleTabs.map((tab) => {
              const TabIcon = tab.Icon;
              return (
                <Button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={tab.id === activeTab.id}
                  variant={tab.id === activeTab.id ? "outline" : "ghost"}
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
          <div className="text-text-neutral-primary flex items-center gap-2 text-sm font-medium">
            <ActiveIcon className="size-4" />
            {activeTab.label}
          </div>
        )}
        <Button
          type="button"
          variant="ghost"
          size="icon-sm"
          aria-label="Close side panel"
          className="ml-auto"
          onClick={() => closePanel()}
        >
          <X />
        </Button>
      </div>
      {/* Content stays mounted after the first open so scroll position and
          composer drafts survive closes. [contain:layout] traps streamdown's
          fixed fullscreen overlay inside the panel (same trap as the page). */}
      <div className="relative min-h-0 flex-1 [contain:layout]">
        {hasBeenOpened ? (
          <Suspense fallback={<SidePanelLoadingFallback />}>
            <ActiveContent />
          </Suspense>
        ) : null}
      </div>
    </aside>
  );
}

function SidePanelLoadingFallback() {
  return (
    <div className="flex h-full flex-col gap-4 p-4">
      <Skeleton className="h-8 w-1/2" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-8 w-2/3" />
    </div>
  );
}
