"use client";

import { KeyRound, Lock } from "lucide-react";
import Link from "next/link";

import { Button } from "@/components/shadcn/button/button";
import {
  STATUS_PANEL_LAYOUT,
  StatusPanel,
  StatusPanelActions,
  StatusPanelBody,
  StatusPanelDescription,
  StatusPanelIcon,
  type StatusPanelLayout,
  StatusPanelTitle,
} from "@/components/shadcn/status-panel";
import { useAuth } from "@/hooks/use-auth";
import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

interface RegistryUpgradePromptProps {
  layout?: StatusPanelLayout;
}

export function RegistryUpgradePrompt({
  layout = STATUS_PANEL_LAYOUT.CENTERED,
}: RegistryUpgradePromptProps) {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <StatusPanel layout={layout}>
      <StatusPanelIcon>
        <Lock />
      </StatusPanelIcon>
      <StatusPanelBody>
        <StatusPanelTitle>Registry is available on paid plans</StatusPanelTitle>
        <StatusPanelDescription>
          Unlock custom providers, security checks, and compliance frameworks.
        </StatusPanelDescription>
      </StatusPanelBody>
      <StatusPanelActions>
        <Button
          size={layout === STATUS_PANEL_LAYOUT.INLINE ? "sm" : "default"}
          type="button"
          onClick={() => openCloudUpgrade(PAID_PLAN_UPGRADE_FEATURE.REGISTRY)}
        >
          Unlock Registry
        </Button>
      </StatusPanelActions>
    </StatusPanel>
  );
}

export function RegistrySetupPrompt() {
  const { permissions } = useAuth();
  const canManage = permissions.manage_registry === true;

  return (
    <StatusPanel layout={STATUS_PANEL_LAYOUT.INLINE}>
      <StatusPanelIcon>
        <KeyRound />
      </StatusPanelIcon>
      <StatusPanelBody>
        <StatusPanelTitle>Registry is not connected yet</StatusPanelTitle>
        <StatusPanelDescription>
          {canManage
            ? "Connect your Registry API key to load custom providers."
            : "Ask an administrator to connect Registry before adding custom providers."}
        </StatusPanelDescription>
      </StatusPanelBody>
      {canManage && (
        <StatusPanelActions>
          <Button asChild size="sm" variant="outline">
            <Link href="/registry">Connect Registry</Link>
          </Button>
        </StatusPanelActions>
      )}
    </StatusPanel>
  );
}
