"use client";

import type { ComponentType, ReactNode } from "react";
import { Suspense, useState } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "./tabs";

export interface TabItem {
  id: string;
  label: string;
  icon?: ReactNode;
  content: ComponentType<{ isActive: boolean }>;
  contentProps?: Record<string, unknown>;
}

interface GenericTabsProps {
  tabs: TabItem[];
  defaultTabId?: string;
  className?: string;
  listClassName?: string;
  triggerClassName?: string;
  contentClassName?: string;
  onTabChange?: (tabId: string) => void;
}

/**
 * A generic tabs component that accepts an array of tab objects with lazy-loaded content.
 *
 * @example
 * const tabs: TabItem[] = [
 *   {
 *     id: "tab-1",
 *     label: "Tab 1",
 *     content: lazy(() => import("./Tab1Content")),
 *     contentProps: { key: "value" }
 *   },
 *   {
 *     id: "tab-2",
 *     label: "Tab 2",
 *     content: lazy(() => import("./Tab2Content"))
 *   }
 * ];
 *
 * <GenericTabs tabs={tabs} defaultTabId="tab-1" onTabChange={(id) => console.log(id)} />
 */
export function GenericTabs({
  tabs,
  defaultTabId,
  className,
  listClassName,
  triggerClassName,
  contentClassName,
  onTabChange,
}: GenericTabsProps) {
  const [activeTab, setActiveTab] = useState<string>(
    defaultTabId || tabs[0]?.id || "",
  );

  const handleTabChange = (tabId: string) => {
    setActiveTab(tabId);
    onTabChange?.(tabId);
  };

  if (!tabs || tabs.length === 0) {
    return null;
  }

  return (
    <Tabs
      value={activeTab}
      onValueChange={handleTabChange}
      className={className}
    >
      <TabsList className={listClassName}>
        {tabs.map((tab) => (
          <TabsTrigger key={tab.id} value={tab.id} className={triggerClassName}>
            {tab.icon && <span className="mr-1">{tab.icon}</span>}
            {tab.label}
          </TabsTrigger>
        ))}
      </TabsList>

      {tabs.map((tab) => {
        const ContentComponent = tab.content;
        const isActive = activeTab === tab.id;

        return (
          <TabsContent key={tab.id} value={tab.id} className={contentClassName}>
            {isActive && (
              <Suspense fallback={<div>Loading...</div>}>
                <ContentComponent
                  isActive={isActive}
                  {...(tab.contentProps || {})}
                />
              </Suspense>
            )}
          </TabsContent>
        );
      })}
    </Tabs>
  );
}
