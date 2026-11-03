"use client";

import { Tabs, TabsList, TabsTrigger } from "@/components/shadcn/tabs/tabs";
import { isFeatureAvailable } from "@/lib/cloudy/features";
import { isCloud } from "@/lib/shared/env";
import {
  CLOUD_UPGRADE_FEATURE,
  type CloudUpgradeFeature,
} from "@/types/cloud-upgrade";
import { ORGANIZATION_TYPE, type OrgFlowType } from "@/types/organizations";

export const ONBOARDING_METHOD = {
  SINGLE: "single",
  ORGANIZATION: "organization",
} as const;

export type OnboardingMethod =
  (typeof ONBOARDING_METHOD)[keyof typeof ONBOARDING_METHOD];

interface OnboardingTabsCopy {
  ariaLabel: string;
  single: string;
  organization: string;
  upgradeFeature: CloudUpgradeFeature;
}

const ONBOARDING_TABS_COPY = {
  [ORGANIZATION_TYPE.AWS]: {
    ariaLabel: "AWS onboarding method",
    single: "Single AWS Account",
    organization: "Full AWS Organization",
    upgradeFeature: CLOUD_UPGRADE_FEATURE.AWS_ORGANIZATIONS,
  },
  [ORGANIZATION_TYPE.AZURE]: {
    ariaLabel: "Azure onboarding method",
    single: "Single Azure Subscription",
    organization: "Azure Management Group",
    upgradeFeature: CLOUD_UPGRADE_FEATURE.AZURE_ORGANIZATIONS,
  },
  [ORGANIZATION_TYPE.GCP]: {
    ariaLabel: "GCP onboarding method",
    single: "Single GCP Project",
    organization: "Full GCP Organization",
    upgradeFeature: CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS,
  },
} as const satisfies Record<OrgFlowType, OnboardingTabsCopy>;

interface OnboardingMethodTabsProps {
  orgType: OrgFlowType;
  value: OnboardingMethod;
  onSelectSingle?: () => void;
  onSelectOrganizations?: () => void;
}

/** Single account vs. whole organization switch at the top of the connect step. */
export function OnboardingMethodTabs({
  orgType,
  value,
  onSelectSingle,
  onSelectOrganizations,
}: OnboardingMethodTabsProps) {
  const copy = ONBOARDING_TABS_COPY[orgType];
  const orgOnboardingAvailable =
    isCloud() || isFeatureAvailable(copy.upgradeFeature);

  const handleValueChange = (next: string) => {
    if (next === value) return;
    if (next === ONBOARDING_METHOD.SINGLE) {
      onSelectSingle?.();
      return;
    }
    if (orgOnboardingAvailable) onSelectOrganizations?.();
  };

  if (!orgOnboardingAvailable) return null;

  return (
    <Tabs
      value={value}
      onValueChange={handleValueChange}
      activationMode="manual"
    >
      <TabsList aria-label={copy.ariaLabel}>
        <TabsTrigger value={ONBOARDING_METHOD.SINGLE}>
          {copy.single}
        </TabsTrigger>
        <TabsTrigger value={ONBOARDING_METHOD.ORGANIZATION}>
          {copy.organization}
        </TabsTrigger>
      </TabsList>
    </Tabs>
  );
}
