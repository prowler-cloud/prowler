import type { JiraDispatchTaskResult } from "@/types/integrations";
import type { TaskState } from "@/types/tasks";

export interface JiraDispatchSuccessOutcome {
  success: true;
  message: string;
  warning?: string;
  failedFindingIds?: string[];
  /** Findings left alone because they already had an open Jira issue. */
  skippedCount?: number;
}

export interface JiraDispatchFailureOutcome {
  success: false;
  error: string;
  failedFindingIds?: string[];
  skippedCount?: number;
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

export const getJiraDispatchSkippedCount = (
  result: JiraDispatchTaskResult | undefined,
) => {
  if (!result) return 0;
  return Math.max(result.skipped_count ?? 0, getArrayCount(result.skipped));
};

const MAX_SKIPPED_KEYS_IN_MESSAGE = 3;

/**
 * "2 Findings already have an open Jira issue (SEC-1, SEC-2)." or an empty
 * string when nothing was skipped.
 */
export const buildJiraDispatchSkippedMessage = (
  result: JiraDispatchTaskResult | undefined,
) => {
  const skippedCount = getJiraDispatchSkippedCount(result);
  if (skippedCount === 0) return "";

  const keys = Array.from(
    new Set(
      (result?.skipped ?? []).flatMap((entry) =>
        entry.issue_key ? [entry.issue_key] : [],
      ),
    ),
  );
  const shownKeys = keys.slice(0, MAX_SKIPPED_KEYS_IN_MESSAGE);
  const hiddenCount = keys.length - shownKeys.length;
  const keysSuffix =
    shownKeys.length > 0
      ? ` (${shownKeys.join(", ")}${hiddenCount > 0 ? `, +${hiddenCount} more` : ""})`
      : "";

  return `${skippedCount} Finding${skippedCount === 1 ? " already has" : "s already have"} an open Jira issue${keysSuffix}.`;
};

const withSkippedCount = (skippedCount: number) =>
  skippedCount > 0 ? { skippedCount } : {};

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
  const skippedMessage = buildJiraDispatchSkippedMessage(result);

  if (successCount === 0 && skippedMessage) {
    return skippedMessage;
  }

  const created =
    successCount > 1
      ? `${successCount} Jira issues were created or updated successfully.`
      : "Finding successfully sent to Jira!";

  return skippedMessage ? `${created} ${skippedMessage}` : created;
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
  const skippedCount = getJiraDispatchSkippedCount(jiraResult);

  if (state === "completed") {
    const failedCount = getFailedCount(jiraResult);
    if (failedCount > 0) {
      const successCount = getJiraDispatchSuccessCount(jiraResult);
      if (successCount > 0 || skippedCount > 0) {
        return {
          success: true,
          message: buildSuccessMessage(jiraResult),
          warning: buildFailureMessage(jiraResult, failedCount),
          ...withFailedFindingIds(failedFindingIds),
          ...withSkippedCount(skippedCount),
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
        ...withSkippedCount(skippedCount),
      };
    }

    if (
      !jiraResult ||
      (getJiraDispatchSuccessCount(jiraResult) === 0 && skippedCount === 0)
    ) {
      return {
        success: false,
        error:
          "Jira dispatch completed but did not create or update any issues.",
      };
    }

    // Every finding already had an open issue: nothing was created, and that
    // is the expected outcome rather than a failure.
    return {
      success: true,
      message: buildSuccessMessage(jiraResult),
      ...withSkippedCount(skippedCount),
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
