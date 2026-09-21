"use client";

import { Badge } from "@/components/shadcn/badge/badge";
import { Tabs, TabsList, TabsTrigger } from "@/components/shadcn/tabs/tabs";
import { isCloud } from "@/lib/shared/env";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

export const AWS_ONBOARDING_METHOD = {
  SINGLE: "single",
  ORGANIZATION: "organization",
} as const;

export type AwsOnboardingMethod =
  (typeof AWS_ONBOARDING_METHOD)[keyof typeof AWS_ONBOARDING_METHOD];

interface AwsOnboardingMethodTabsProps {
  value: AwsOnboardingMethod;
  onSelectSingle: () => void;
  onSelectOrganizations: () => void;
}

/** Single account vs. whole organization switch shown at the top of both AWS flows. */
export function AwsOnboardingMethodTabs({
  value,
  onSelectSingle,
  onSelectOrganizations,
}: AwsOnboardingMethodTabsProps) {
  const isCloudEnv = isCloud();
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  const handleValueChange = (next: string) => {
    if (next === value) return;
    if (next === AWS_ONBOARDING_METHOD.SINGLE) {
      onSelectSingle();
      return;
    }
    if (isCloudEnv) {
      onSelectOrganizations();
      return;
    }
    openCloudUpgrade(CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS);
  };

  return (
    <Tabs
      value={value}
      onValueChange={handleValueChange}
      activationMode="manual"
    >
      <TabsList aria-label="AWS onboarding method">
        <TabsTrigger value={AWS_ONBOARDING_METHOD.SINGLE}>
          Single AWS Account
        </TabsTrigger>
        <TabsTrigger
          value={AWS_ONBOARDING_METHOD.ORGANIZATION}
          adornment={
            !isCloudEnv && (
              <Badge variant="cloud" size="sm">
                Cloud
              </Badge>
            )
          }
        >
          Full AWS Organization
        </TabsTrigger>
      </TabsList>
    </Tabs>
  );
}
