import { getJiraSelectionBatches } from "@/lib/jira-dispatch-selection";
import {
  JIRA_DISPATCH_MODE,
  JIRA_DISPATCH_TARGET,
  JIRA_TARGET_SELECTION_KIND,
  type JiraDispatchMode,
} from "@/types/integrations";
import type { JiraDispatchModalPayload } from "@/types/jira-dispatch";

export interface JiraDispatchActionState {
  defaultDispatchMode: JiraDispatchMode;
  canChooseGroupedDispatch: boolean;
  requiresUpgrade: boolean;
}

export interface JiraActionLabelCounts {
  findingGroupCount?: number;
  findingCount?: number;
}

export const getJiraDispatchActionState = (
  payload: JiraDispatchModalPayload,
  groupedDispatchEnabled: boolean,
): JiraDispatchActionState => {
  const batches = getJiraSelectionBatches(payload.selection);
  const targetCount = batches.reduce(
    (count, batch) => count + batch.targetIds.length,
    0,
  );
  const hasFindingGroupTargets = batches.some(
    (batch) => batch.targetType === JIRA_DISPATCH_TARGET.CHECK_ID,
  );
  const requiresGroupedFeature =
    hasFindingGroupTargets || batches.length > 1 || targetCount > 1;
  const firstBatch = batches[0];
  const canChooseGroupedDispatch =
    groupedDispatchEnabled &&
    payload.selection.kind !== JIRA_TARGET_SELECTION_KIND.BATCHES &&
    (firstBatch.targetType === JIRA_DISPATCH_TARGET.FINDING_ID
      ? firstBatch.targetIds.length > 1
      : firstBatch.targetIds.length === 1 &&
        (payload.selectedResourceCount ?? 0) > 1);

  return {
    defaultDispatchMode: requiresGroupedFeature
      ? JIRA_DISPATCH_MODE.GROUPED
      : JIRA_DISPATCH_MODE.INDIVIDUAL,
    canChooseGroupedDispatch,
    requiresUpgrade: requiresGroupedFeature && !groupedDispatchEnabled,
  };
};

const buildEntityLabel = (
  count: number,
  singular: string,
  plural: string,
): string | null => {
  if (count === 0) return null;
  return `${count} ${count === 1 ? singular : plural}`;
};

export const buildJiraActionLabel = ({
  findingGroupCount = 0,
  findingCount = 0,
}: JiraActionLabelCounts): string => {
  const entities = [
    buildEntityLabel(findingGroupCount, "Finding Group", "Finding Groups"),
    buildEntityLabel(findingCount, "Finding", "Findings"),
  ].filter(Boolean);

  return entities.length > 0
    ? `Send ${entities.join(" and ")} to Jira`
    : "Send to Jira";
};
