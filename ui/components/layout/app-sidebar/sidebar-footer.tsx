"use client";

import { Cloud } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import { useCloudUpgradeStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

import type { AppSidebarSelectionHandler } from "./types";

interface SidebarFooterProps {
  isCloudEnvironment: boolean;
  onSelect?: AppSidebarSelectionHandler;
}

export function SidebarFooter({
  isCloudEnvironment,
  onSelect,
}: SidebarFooterProps) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );
  const version = process.env.NEXT_PUBLIC_PROWLER_RELEASE_VERSION;

  return (
    <div className="shrink-0 px-3 pb-4">
      {!isCloudEnvironment && (
        <div className="pt-4 pb-3">
          <Button
            type="button"
            variant="default"
            className="w-full"
            onClick={() => {
              openCloudUpgrade(
                CLOUD_UPGRADE_FEATURE.GENERAL,
                onSelect?.() ?? undefined,
              );
            }}
          >
            <Cloud aria-hidden="true" className="size-4" />
            Explore Prowler Cloud
          </Button>
        </div>
      )}

      <div className="border-border-neutral-secondary text-text-neutral-tertiary flex min-h-9 items-center border-t pt-3 text-[11px]">
        {isCloudEnvironment && (
          <Link
            href="https://status.prowler.com"
            target="_blank"
            rel="noopener noreferrer"
            className="hover:text-text-neutral-primary min-w-0 flex-1 transition-colors"
            onClick={onSelect}
          >
            <span className="truncate">Service status</span>
          </Link>
        )}
        <span className="ml-auto font-mono">{version}</span>
      </div>
    </div>
  );
}
