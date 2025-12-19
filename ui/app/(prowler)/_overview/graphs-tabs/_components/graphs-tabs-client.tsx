"use client";

import { useRef, useState } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

import { GRAPH_TABS, type TabId } from "../_config/graphs-tabs-config";

interface GraphsTabsClientProps {
  tabsContent: Record<TabId, React.ReactNode>;
}

export const GraphsTabsClient = ({ tabsContent }: GraphsTabsClientProps) => {
  const [activeTab, setActiveTab] = useState<TabId>("findings");
  const contentRef = useRef<HTMLDivElement>(null);

  const handleValueChange = (value: string) => {
    setActiveTab(value as TabId);

    // Scroll to the end of the tab content after a short delay for render
    setTimeout(() => {
      contentRef.current?.scrollIntoView({
        behavior: "smooth",
        block: "end",
      });
    }, 100);
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

      <div ref={contentRef}>
        {GRAPH_TABS.map((tab) =>
          activeTab === tab.id ? (
            <TabsContent
              key={tab.id}
              value={tab.id}
              className="mt-10 flex flex-1 overflow-visible"
            >
              {tabsContent[tab.id]}
            </TabsContent>
          ) : null,
        )}
      </div>
    </Tabs>
  );
};
