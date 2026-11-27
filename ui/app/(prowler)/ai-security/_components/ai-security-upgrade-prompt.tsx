"use client";

import { Lock } from "lucide-react";

import {
  Button,
  StatusPanel,
  StatusPanelActions,
  StatusPanelBody,
  StatusPanelDescription,
  StatusPanelIcon,
  StatusPanelTitle,
} from "@/components/shadcn";
import { useCloudUpgradeStore } from "@/store/cloud-upgrade/store";
import { PAID_PLAN_UPGRADE_FEATURE } from "@/types/cloud-upgrade";

export function AiSecurityUpgradePrompt() {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );

  return (
    <StatusPanel>
      <StatusPanelIcon>
        <Lock />
      </StatusPanelIcon>
      <StatusPanelBody>
        <StatusPanelTitle>
          AI Security is available on paid plans
        </StatusPanelTitle>
        <StatusPanelDescription>
          Scan your Claude, OpenAI and ChatGPT organizations and score them
          against the AI frameworks.
        </StatusPanelDescription>
      </StatusPanelBody>
      <StatusPanelActions>
        <Button
          type="button"
          onClick={() =>
            openCloudUpgrade(PAID_PLAN_UPGRADE_FEATURE.AI_SECURITY)
          }
        >
          Unlock AI Security
        </Button>
      </StatusPanelActions>
    </StatusPanel>
  );
}
