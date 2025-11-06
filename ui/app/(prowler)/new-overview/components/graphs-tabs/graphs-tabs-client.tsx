"use client";

import { useState } from "react";

import {
  Tabs,
  TabsList,
  TabsTrigger,
  TabsContent,
} from "@/components/shadcn";

import { GRAPH_TABS, type TabId } from "./graphs-tabs-config";

interface GraphsTabsClientProps {
  tabsContent: Record<TabId, React.ReactNode>;
}

export const GraphsTabsClient = ({ tabsContent }: GraphsTabsClientProps) => {
  const [activeTab, setActiveTab] = useState<TabId>("threat-map");

  return (
    <Tabs value={activeTab} onValueChange={setActiveTab} className="flex flex-1 flex-col">
      <TabsList className={`grid w-full grid-cols-${GRAPH_TABS.length}`}>
        {GRAPH_TABS.map((tab) => (
          <TabsTrigger key={tab.id} value={tab.id}>
            {tab.label}
          </TabsTrigger>
        ))}
      </TabsList>

      {GRAPH_TABS.map((tab) =>
        activeTab === tab.id ? (
          <TabsContent key={tab.id} value={tab.id} className="flex flex-1 overflow-hidden">
            {tabsContent[tab.id]}
          </TabsContent>
        ) : null,
      )}
    </Tabs>
  );
};
