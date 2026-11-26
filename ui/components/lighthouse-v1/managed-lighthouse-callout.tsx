"use client";

import { Sparkles } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn/card/card";
import { PremiumBadge } from "@/components/shared/premium-badge";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

const LIGHTHOUSE_EDITIONS = [
  {
    name: "Your Lighthouse AI",
    detail: "Bring your own LLM key. Included in Local Server.",
  },
  {
    name: "Managed Lighthouse AI",
    detail:
      "No keys to provision, persistent sessions, and a hosted remote MCP server.",
  },
] as const;

export const ManagedLighthouseCallout = () => {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <Card variant="inner" padding="lg">
      <CardHeader className="gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Sparkles
            aria-hidden="true"
            className="text-text-neutral-primary size-5"
          />
          <CardTitle>Managed Lighthouse AI</CardTitle>
          <PremiumBadge feature={CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI} />
        </div>
      </CardHeader>
      <CardContent className="flex flex-col items-start gap-4">
        <dl className="grid w-full gap-3 sm:grid-cols-2">
          {LIGHTHOUSE_EDITIONS.map((edition) => (
            <div
              key={edition.name}
              className="border-border-neutral-secondary rounded-lg border p-3"
            >
              <dt className="text-text-neutral-primary text-sm font-medium">
                {edition.name}
              </dt>
              <dd className="text-text-neutral-secondary text-sm">
                {edition.detail}
              </dd>
            </div>
          ))}
        </dl>
        <Button
          type="button"
          variant="default"
          onClick={() => openCloudUpgrade(CLOUD_UPGRADE_FEATURE.LIGHTHOUSE_AI)}
        >
          See Managed Lighthouse AI
        </Button>
      </CardContent>
    </Card>
  );
};
