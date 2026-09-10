"use client";

import { Box, Boxes } from "lucide-react";

import { RadioCard } from "@/components/providers/radio-card";
import { Badge } from "@/components/shadcn/badge/badge";
import { isCloud } from "@/lib/shared/env";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

interface GcpMethodSelectorProps {
  onSelectSingle: () => void;
  onSelectOrganizations: () => void;
}

export function GcpMethodSelector({
  onSelectSingle,
  onSelectOrganizations,
}: GcpMethodSelectorProps) {
  const isCloudEnv = isCloud();
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <div className="flex flex-col gap-3">
      <p className="text-muted-foreground text-sm">
        Select a method to add your projects to Prowler.
      </p>

      <RadioCard
        icon={Box}
        title="Add A Single GCP Project"
        onClick={onSelectSingle}
      />

      <RadioCard
        icon={Boxes}
        title="Add Multiple Projects With GCP Organization"
        onClick={() =>
          isCloudEnv
            ? onSelectOrganizations()
            : openCloudUpgrade(CLOUD_UPGRADE_FEATURE.GCP_ORGANIZATIONS)
        }
      >
        {!isCloudEnv && <Badge variant="cloud">Cloud</Badge>}
      </RadioCard>
    </div>
  );
}
