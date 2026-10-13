"use client";

import { Box, Boxes } from "lucide-react";

import { RadioCard } from "@/components/providers/radio-card";
import { Badge } from "@/components/shadcn/badge/badge";
import { isCloud } from "@/lib/shared/env";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

interface AzureMethodSelectorProps {
  onSelectSingle: () => void;
  onSelectOrganizations: () => void;
}

export function AzureMethodSelector({
  onSelectSingle,
  onSelectOrganizations,
}: AzureMethodSelectorProps) {
  const isCloudEnv = isCloud();
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <div className="flex flex-col gap-3">
      <p className="text-muted-foreground text-sm">
        Select a method to add your subscriptions to Prowler.
      </p>

      <RadioCard
        icon={Box}
        title="Add A Single Azure Subscription"
        onClick={onSelectSingle}
      />

      <RadioCard
        icon={Boxes}
        title="Add Multiple Subscriptions With Azure Management Group"
        onClick={() =>
          isCloudEnv
            ? onSelectOrganizations()
            : openCloudUpgrade(CLOUD_UPGRADE_FEATURE.AZURE_ORGANIZATIONS)
        }
      >
        {!isCloudEnv && <Badge variant="cloud">Cloud</Badge>}
      </RadioCard>
    </div>
  );
}
