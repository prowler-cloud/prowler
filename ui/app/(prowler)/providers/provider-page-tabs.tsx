"use client";

import { ReactNode, useState } from "react";

import { useRouter } from "next/navigation";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/shadcn";

const PROVIDER_TAB = {
  ACCOUNTS: "accounts",
  ACCOUNT_GROUPS: "account-groups",
} as const;

type ProviderTab = (typeof PROVIDER_TAB)[keyof typeof PROVIDER_TAB];

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
  const [currentTab, setCurrentTab] = useState<ProviderTab>(activeTab);
  const router = useRouter();

  const handleTabChange = (tab: string) => {
    const typedTab = tab as ProviderTab;
    setCurrentTab(typedTab);
    if (typedTab === PROVIDER_TAB.ACCOUNTS) {
      router.push("/providers");
    } else {
      router.push(`/providers?tab=${typedTab}`);
    }
  };

  return (
    <Tabs
      value={currentTab}
      onValueChange={handleTabChange}
      className="flex w-full flex-col gap-6"
    >
      <TabsList>
        <TabsTrigger value={PROVIDER_TAB.ACCOUNTS}>Accounts</TabsTrigger>
        <TabsTrigger value={PROVIDER_TAB.ACCOUNT_GROUPS}>
          Account Groups
        </TabsTrigger>
      </TabsList>

      <TabsContent value={PROVIDER_TAB.ACCOUNTS} className="mt-0">
        {accountsContent}
      </TabsContent>

      <TabsContent value={PROVIDER_TAB.ACCOUNT_GROUPS} className="mt-0">
        {accountGroupsContent}
      </TabsContent>
    </Tabs>
  );
};

export { PROVIDER_TAB };
export type { ProviderTab };
