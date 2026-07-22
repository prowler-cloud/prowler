import {
  JIRA_TARGET_SELECTION_KIND,
  type JiraBatchSelection,
  type JiraDispatchTarget,
  type JiraDispatchTargetBatch,
  type JiraSelection,
  type NonEmptyStringArray,
} from "@/types/integrations";

export interface JiraDispatchTargetBatchInput {
  targetIds: string[];
  targetType: JiraDispatchTarget;
  dispatchMode?: JiraDispatchTargetBatch["dispatchMode"];
}

export const toNonEmptyStringArray = (
  values: string[],
): NonEmptyStringArray | null => {
  const [first, ...rest] = values.filter(Boolean);
  return first ? [first, ...rest] : null;
};

export const createJiraTargetSelection = (
  targetIds: string[],
  targetType: JiraDispatchTarget,
): JiraSelection | null => {
  const nonEmptyTargetIds = toNonEmptyStringArray(targetIds);
  if (!nonEmptyTargetIds) return null;

  if (nonEmptyTargetIds.length === 1) {
    return {
      kind: JIRA_TARGET_SELECTION_KIND.SINGLE,
      targetId: nonEmptyTargetIds[0],
      targetType,
    };
  }

  return {
    kind: JIRA_TARGET_SELECTION_KIND.TARGET_LIST,
    targetIds: nonEmptyTargetIds,
    targetType,
  };
};

export const createJiraBatchSelection = (
  batches: JiraDispatchTargetBatchInput[],
): JiraBatchSelection | null => {
  const normalizedBatches = batches.flatMap((batch) => {
    const targetIds = toNonEmptyStringArray(batch.targetIds);
    return targetIds ? [{ ...batch, targetIds }] : [];
  });
  const [firstBatch, ...remainingBatches] = normalizedBatches;

  return firstBatch
    ? {
        kind: JIRA_TARGET_SELECTION_KIND.BATCHES,
        batches: [firstBatch, ...remainingBatches],
      }
    : null;
};

export const getJiraSelectionBatches = (
  selection: JiraSelection,
): [JiraDispatchTargetBatch, ...JiraDispatchTargetBatch[]] => {
  if (selection.kind === JIRA_TARGET_SELECTION_KIND.BATCHES) {
    return selection.batches;
  }

  if (selection.kind === JIRA_TARGET_SELECTION_KIND.SINGLE) {
    return [
      {
        targetIds: [selection.targetId],
        targetType: selection.targetType,
      },
    ];
  }

  return [
    {
      targetIds: selection.targetIds,
      targetType: selection.targetType,
    },
  ];
};
