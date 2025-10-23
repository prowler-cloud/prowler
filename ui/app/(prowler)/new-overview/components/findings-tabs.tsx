"use client";

import { Eye, Settings } from "lucide-react";

import { GenericTabs, type TabItem } from "@/components/shadcn";

import { AnalyticsTab } from "./analytics-tab";
import { CheckFindings } from "./check-findings";

interface FindingsTabsProps {
  failFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
  passFindingsData: {
    total: number;
    new: number;
    muted: number;
  };
}

export function FindingsTabs({
  failFindingsData,
  passFindingsData,
}: FindingsTabsProps) {
  const tabs: TabItem[] = [
    {
      id: "overview",
      label: "Overview",
      icon: <Eye size={16} />,
      content: (_props) => (
        <CheckFindings
          failFindingsData={failFindingsData}
          passFindingsData={passFindingsData}
        />
      ),
    },
    {
      id: "analytics",
      label: "Analytics",
      icon: <Settings size={16} />,
      content: (_props) => (
        <AnalyticsTab
          isActive
          failFindingsData={failFindingsData}
          passFindingsData={passFindingsData}
        />
      ),
    },
  ];

  return (
    <GenericTabs
      tabs={tabs}
      defaultTabId="overview"
      onTabChange={(tabId) => {
        // Tab change detected
        void tabId;
      }}
    />
  );
}
