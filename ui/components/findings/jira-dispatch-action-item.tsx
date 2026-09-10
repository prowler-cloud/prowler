"use client";

import { JiraIcon } from "@/components/icons/services/IconServices";
import { ActionDropdownItem } from "@/components/shadcn/dropdown";
import {
  isGroupedJiraDispatchEnabled,
  PROWLER_CLOUD_ONLY_TOOLTIP,
} from "@/lib/deployment";
import { getJiraDispatchActionState } from "@/lib/jira-dispatch-action";
import { useCloudUpgradeStore, useJiraDispatchStore } from "@/store";
import { CLOUD_UPGRADE_FEATURE } from "@/types/cloud-upgrade";
import type { JiraDispatchModalPayload } from "@/types/jira-dispatch";

interface JiraDispatchActionItemProps {
  label: string;
  payload: JiraDispatchModalPayload | null | undefined;
}

export const JiraDispatchActionItem = ({
  label,
  payload,
}: JiraDispatchActionItemProps) => {
  const openCloudUpgrade = useCloudUpgradeStore(
    (state) => state.openCloudUpgrade,
  );
  const openJiraDispatch = useJiraDispatchStore(
    (state) => state.openJiraDispatch,
  );

  if (!payload) return null;

  const { requiresUpgrade } = getJiraDispatchActionState(
    payload,
    isGroupedJiraDispatchEnabled(),
  );

  const handleSelect = () => {
    if (requiresUpgrade) {
      openCloudUpgrade(CLOUD_UPGRADE_FEATURE.JIRA_DISPATCH);
      return;
    }

    openJiraDispatch(payload);
  };

  return (
    <ActionDropdownItem
      icon={<JiraIcon size={20} />}
      label={label}
      aria-label={label}
      tooltip={requiresUpgrade ? PROWLER_CLOUD_ONLY_TOOLTIP : undefined}
      onSelect={handleSelect}
    />
  );
};
