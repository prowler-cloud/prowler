"use client";

import { Sparkles } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";
import { CloudFeatureBadge } from "@/components/shared/cloud-feature-badge";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

export const ManagedLighthouseCallout = () => {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <Card variant="inner" padding="lg">
      <CardHeader className="gap-3">
        <div className="flex items-center gap-2">
          <Sparkles
            aria-hidden="true"
            className="text-text-neutral-primary size-5"
          />
          <CardTitle>Skip the setup with Prowler Cloud</CardTitle>
          <CloudFeatureBadge label="Cloud" size="sm" />
        </div>
      </CardHeader>
      <CardContent className="flex flex-col items-start gap-4">
        <p className="text-text-neutral-secondary text-sm">
          Prowler Cloud includes managed OpenAI access with no API keys to
          provision, plus a hosted remote MCP server to automate security
          workflows.
        </p>
        <Button
          type="button"
          variant="outline"
          onClick={() => openCloudUpgrade(CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI)}
        >
          Explore the fully Managed Lighthouse AI
        </Button>
      </CardContent>
    </Card>
  );
};
