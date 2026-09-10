"use client";

import { isGroupedJiraDispatchEnabled } from "@/lib/deployment";
import { getJiraDispatchActionState } from "@/lib/jira-dispatch-action";
import { useJiraDispatchStore } from "@/store";

import { SendToJiraModal } from "./send-to-jira-modal";

export const JiraDispatchModalHost = () => {
  const activePayload = useJiraDispatchStore((state) => state.activePayload);
  const closeJiraDispatch = useJiraDispatchStore(
    (state) => state.closeJiraDispatch,
  );

  if (!activePayload) return null;

  const { defaultDispatchMode, canChooseGroupedDispatch } =
    getJiraDispatchActionState(activePayload, isGroupedJiraDispatchEnabled());

  return (
    <SendToJiraModal
      isOpen
      onOpenChange={(open) => !open && closeJiraDispatch()}
      selection={activePayload.selection}
      findingTitle={activePayload.findingTitle}
      defaultDispatchMode={defaultDispatchMode}
      canChooseGroupedDispatch={canChooseGroupedDispatch}
      isFindingGroupSelection={activePayload.isFindingGroupSelection}
      selectedResourceCount={activePayload.selectedResourceCount}
      description={activePayload.description}
    />
  );
};
