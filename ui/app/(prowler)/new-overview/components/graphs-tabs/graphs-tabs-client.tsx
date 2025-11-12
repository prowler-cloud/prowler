"use client";

import { useState } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

import { GRAPH_TABS, type TabId } from "./graphs-tabs-config";

interface GraphsTabsClientProps {
  tabsContent: Record<TabId, React.ReactNode>;
}

export const GraphsTabsClient = ({ tabsContent }: GraphsTabsClientProps) => {
  const [activeTab, setActiveTab] = useState<TabId>("threat-map");

  const handleValueChange = (value: string) => {
    setActiveTab(value as TabId);
  };

  return (
    <Tabs
      value={activeTab}
      onValueChange={handleValueChange}
      className="flex flex-1 flex-col"
    >
      <TabsList className="flex w-fit gap-2">
        {GRAPH_TABS.map((tab) => (
          <TabsTrigger
            key={tab.id}
            value={tab.id}
            className="whitespace-nowrap"
          >
            {tab.label}
          </TabsTrigger>
        ))}
      </TabsList>

      {GRAPH_TABS.map((tab) =>
        activeTab === tab.id ? (
          <TabsContent
            key={tab.id}
            value={tab.id}
            className="mt-4 flex flex-1 overflow-visible"
          >
            {tabsContent[tab.id]}
          </TabsContent>
        ) : null,
      )}
    </Tabs>
  );
};
