"use client";

import { lazy, type ReactNode, Suspense, useState } from "react";

import { LighthouseIcon } from "@/components/icons";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";
import { Skeleton } from "@/components/shadcn/skeleton/skeleton";
import { isCloud } from "@/lib/shared/env";

const DETAIL_DRAWER_TAB = {
  DETAILS: "details",
  ASK_AI: "ask-ai",
} as const;

type DetailDrawerTabId =
  (typeof DETAIL_DRAWER_TAB)[keyof typeof DETAIL_DRAWER_TAB];

// Lazy so the chat bundle never loads for users who stay on the Details tab.
const LazyLighthousePanelChat = lazy(() =>
  import(
    "@/app/(prowler)/lighthouse/_components/panel/lighthouse-panel-chat"
  ).then((module) => ({ default: module.LighthousePanelChat })),
);

interface DetailDrawerTabsProps {
  children: ReactNode;
}

// Wraps a detail drawer's content with a [ Details | Ask AI ] strip. The AI
// tab binds to the same singleton chat store as the global side panel, so it
// is the same conversation on every surface. In OSS the strip disappears
// entirely and the detail content renders untouched.
export function DetailDrawerTabs({ children }: DetailDrawerTabsProps) {
  // Drawer content mounts on each open, so every open starts on Details.
  const [activeTab, setActiveTab] = useState<DetailDrawerTabId>(
    DETAIL_DRAWER_TAB.DETAILS,
  );

  if (!isCloud()) {
    return <>{children}</>;
  }

  return (
    <Tabs
      value={activeTab}
      onValueChange={(value: string) =>
        setActiveTab(value as DetailDrawerTabId)
      }
      className="flex h-full min-h-0 flex-col"
    >
      {/* mr-8 keeps the strip clear of the drawer's absolute close button. */}
      <TabsList className="mr-8 w-auto self-start">
        <TabsTrigger value={DETAIL_DRAWER_TAB.DETAILS}>Details</TabsTrigger>
        <TabsTrigger
          value={DETAIL_DRAWER_TAB.ASK_AI}
          data-testid="detail-drawer-ask-ai-tab"
        >
          <LighthouseIcon className="size-4" />
          Ask AI
        </TabsTrigger>
      </TabsList>
      {/* forceMount keeps the details pane alive (Radix hides it with the
          native hidden attribute) so carousel index, inner tabs and scroll
          survive switching to Ask AI and back. */}
      <TabsContent
        forceMount
        value={DETAIL_DRAWER_TAB.DETAILS}
        className="min-h-0 flex-1 overflow-hidden"
      >
        {children}
      </TabsContent>
      {/* [contain:layout] traps streamdown's fixed fullscreen overlay inside
          the drawer (same trap as the page and the global panel). */}
      <TabsContent
        value={DETAIL_DRAWER_TAB.ASK_AI}
        className="min-h-0 flex-1 overflow-hidden [contain:layout]"
      >
        <Suspense fallback={<DetailDrawerChatFallback />}>
          <LazyLighthousePanelChat />
        </Suspense>
      </TabsContent>
    </Tabs>
  );
}

function DetailDrawerChatFallback() {
  return (
    <div className="flex h-full flex-col gap-4 p-4">
      <Skeleton className="h-8 w-1/2" />
      <Skeleton className="h-24 w-full" />
      <Skeleton className="h-8 w-2/3" />
    </div>
  );
}
