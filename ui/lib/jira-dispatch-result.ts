import type { JiraDispatchTaskResult } from "@/types/integrations";
import type { TaskState } from "@/types/tasks";

export interface JiraDispatchSuccessOutcome {
  success: true;
  message: string;
  warning?: string;
  failedFindingIds?: string[];
}

export interface JiraDispatchFailureOutcome {
  success: false;
  error: string;
  failedFindingIds?: string[];
}

export type JiraDispatchOutcome =
  | JiraDispatchSuccessOutcome
  | JiraDispatchFailureOutcome;

const getArrayCount = (value: unknown[] | undefined) =>
  Array.isArray(value) ? value.length : 0;

const getFailedCount = (result: JiraDispatchTaskResult | undefined) => {
  if (!result) return 0;
  return Math.max(
    result.failed_count ?? 0,
    getArrayCount(result.failed_groups),
    getArrayCount(result.failed_batches),
    getArrayCount(result.failed_finding_ids),
  );
};

export const getJiraDispatchSuccessCount = (
  result: JiraDispatchTaskResult | undefined,
) => {
  if (!result) return 0;

  const createdCount = Math.max(
    result.created_count ?? 0,
    getArrayCount(result.created_issues),
  );
  const updatedCount = Math.max(
    result.updated_count ?? 0,
    getArrayCount(result.updated_issues),
  );

  return Math.max(
    result.successful_count ?? 0,
    createdCount + updatedCount,
    result.issue_key || result.issue_url ? 1 : 0,
  );
};

const ensureSentence = (message: string) =>
  /[.!?]$/.test(message.trim()) ? message.trim() : `${message.trim()}.`;

const buildFailureMessage = (
  result: JiraDispatchTaskResult | undefined,
  failedCount: number,
) => {
  const successCount = getJiraDispatchSuccessCount(result);
  const summary = `Jira dispatch completed with ${failedCount} failed and ${successCount} created/updated issue${successCount === 1 ? "" : "s"}.`;

  return result?.error ? `${ensureSentence(result.error)} ${summary}` : summary;
};

const buildSuccessMessage = (result: JiraDispatchTaskResult | undefined) => {
  const successCount = getJiraDispatchSuccessCount(result);
  if (successCount > 1) {
    return `${successCount} Jira issues were created or updated successfully.`;
  }

  return "Finding successfully sent to Jira!";
};

const getFailedFindingIds = (result: JiraDispatchTaskResult | undefined) =>
  Array.from(new Set(result?.failed_finding_ids?.filter(Boolean) ?? []));

const withFailedFindingIds = (failedFindingIds: string[]) =>
  failedFindingIds.length > 0 ? { failedFindingIds } : {};

export const evaluateJiraDispatchTask = (
  state: TaskState,
  result: JiraDispatchTaskResult | null | undefined,
): JiraDispatchOutcome => {
  const jiraResult = result ?? undefined;
  const failedFindingIds = getFailedFindingIds(jiraResult);

  if (state === "completed") {
    const failedCount = getFailedCount(jiraResult);
    if (failedCount > 0) {
      const successCount = getJiraDispatchSuccessCount(jiraResult);
      if (successCount > 0) {
        return {
          success: true,
          message: buildSuccessMessage(jiraResult),
          warning: buildFailureMessage(jiraResult, failedCount),
          ...withFailedFindingIds(failedFindingIds),
        };
      }

      return {
        success: false,
        error: buildFailureMessage(jiraResult, failedCount),
        ...withFailedFindingIds(failedFindingIds),
      };
    }

    if (jiraResult?.success === false || jiraResult?.error) {
      return {
        success: false,
        error: jiraResult.error || "Failed to create Jira issue.",
        ...withFailedFindingIds(failedFindingIds),
      };
    }

    if (!jiraResult || getJiraDispatchSuccessCount(jiraResult) === 0) {
      return {
        success: false,
        error:
          "Jira dispatch completed but did not create or update any issues.",
      };
    }

    return {
      success: true,
      message: buildSuccessMessage(jiraResult),
    };
  }

  if (state === "failed") {
    return {
      success: false,
      error: jiraResult?.error || "Task failed.",
      ...withFailedFindingIds(failedFindingIds),
    };
  }

  return { success: false, error: `Unknown task state: ${state}` };
};
