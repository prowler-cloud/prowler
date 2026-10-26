"use client";

import { Send } from "lucide-react";
import { useState } from "react";

import { SendToJiraModal } from "@/components/findings/send-to-jira-modal";
import { Button } from "@/components/shadcn/button/button";
import {
  JIRA_DISPATCH_MODE,
  JIRA_DISPATCH_TARGET,
  JIRA_TARGET_SELECTION_KIND,
} from "@/types/integrations";

interface IssueSendToJiraProps {
  title: string;
  /** Finding ids, not uids: the dispatch endpoint targets rows by id. */
  findingIds: string[];
}

/**
 * Grouped by default: four tickets for one bucket would undo the fold. The
 * grouped dispatch makes one ticket per check, not per selection, so a path
 * spanning two checks gets two tickets.
 */
export const IssueSendToJira = ({
  title,
  findingIds,
}: IssueSendToJiraProps) => {
  const [open, setOpen] = useState(false);
  const [first, ...rest] = findingIds;
  if (!first) return null;

  return (
    <>
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        <Send aria-hidden="true" />
        Send to Jira
      </Button>
      <SendToJiraModal
        isOpen={open}
        onOpenChange={setOpen}
        findingTitle={title}
        selection={{
          kind: JIRA_TARGET_SELECTION_KIND.TARGET_LIST,
          targetIds: [first, ...rest],
          targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
        }}
        defaultDispatchMode={JIRA_DISPATCH_MODE.GROUPED}
        canChooseGroupedDispatch
        description={`One ticket per check on this attack path, grouping its ${findingIds.length} ${
          findingIds.length === 1 ? "finding" : "findings"
        }.`}
      />
    </>
  );
};
