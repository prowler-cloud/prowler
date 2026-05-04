"use client";

import { useRouter } from "next/navigation";
import { ReactNode } from "react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

import { PROVIDER_TAB, type ProviderTab } from "./provider-page-tabs.shared";

interface ProviderPageTabsProps {
  activeTab: ProviderTab;
  accountsContent: ReactNode;
  accountGroupsContent: ReactNode;
}

export const ProviderPageTabs = ({
  activeTab,
  accountsContent,
  accountGroupsContent,
}: ProviderPageTabsProps) => {
  const router = useRouter();

  const handleTabChange = (tab: string) => {
    const typedTab = tab as ProviderTab;

    if (typedTab === activeTab) {
      return;
    }

    if (typedTab === PROVIDER_TAB.PROVIDERS) {
      router.push("/providers");
    } else {
      router.push(`/providers?tab=${typedTab}`);
    }
  };

  return (
    <Tabs
      value={activeTab}
      onValueChange={handleTabChange}
      className="flex w-full flex-col gap-6"
    >
      <TabsList>
        <TabsTrigger value={PROVIDER_TAB.PROVIDERS}>Providers</TabsTrigger>
        <TabsTrigger value={PROVIDER_TAB.PROVIDER_GROUPS}>
          Provider Groups
        </TabsTrigger>
      </TabsList>

      <TabsContent value={PROVIDER_TAB.PROVIDERS} className="mt-0">
        {accountsContent}
      </TabsContent>

      <TabsContent value={PROVIDER_TAB.PROVIDER_GROUPS} className="mt-0">
        {accountGroupsContent}
      </TabsContent>
    </Tabs>
  );
};
