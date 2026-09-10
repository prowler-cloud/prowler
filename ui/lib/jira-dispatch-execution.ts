import { sendJiraDispatch } from "@/actions/integrations/jira-dispatch";
import {
  evaluateJiraDispatchTask,
  getJiraDispatchSuccessCount,
} from "@/lib/jira-dispatch-result";
import { buildJiraDispatchTaskMeta } from "@/lib/jira-dispatch-task";
import {
  TASK_WATCHER_STATUS,
  type TaskTrackingResult,
  trackAndPollTask,
} from "@/store/task-watcher/store";
import {
  JIRA_DISPATCH_MODE,
  JIRA_DISPATCH_TARGET,
  JIRA_DISPATCH_TASK_KIND,
  type JiraDispatchMode,
  type JiraDispatchTargetBatch,
  type JiraDispatchTaskResult,
} from "@/types/integrations";

export interface JiraDispatchSettings {
  integrationId: string;
  projectKey: string;
  issueType: string;
  dispatchMode: JiraDispatchMode;
}

export interface JiraDispatchExecutionResult {
  startedTaskCount: number;
  successfulTaskCount: number;
  successfulIssueCount: number;
  successMessage?: string;
  warnings: string[];
  errors: string[];
  retryBatch?: JiraDispatchTargetBatch;
}

interface JiraTrackedOutcome {
  success: boolean;
  message?: string;
  error?: string;
  warning?: string;
  failedFindingIds?: string[];
  successfulCount?: number;
}

export function getJiraRetryBatch(
  failedFindingIds: string[] | undefined,
): JiraDispatchTargetBatch | undefined {
  const [firstTargetId, ...remainingTargetIds] = Array.from(
    new Set(failedFindingIds?.filter(Boolean) ?? []),
  );
  if (!firstTargetId) return undefined;

  return {
    targetIds: [firstTargetId, ...remainingTargetIds],
    targetType: JIRA_DISPATCH_TARGET.FINDING_ID,
    dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
  };
}

export async function executeJiraDispatchBatches(
  batches: JiraDispatchTargetBatch[],
  settings: JiraDispatchSettings,
  options: { notifyHandler?: boolean } = {},
): Promise<JiraDispatchExecutionResult> {
  const startedTasks: Array<{
    taskId: string;
    dispatchMode: JiraDispatchMode;
  }> = [];
  const launchErrors: string[] = [];

  for (const batch of batches) {
    const dispatchMode = batch.dispatchMode ?? settings.dispatchMode;
    try {
      const result = await sendJiraDispatch({
        integrationId: settings.integrationId,
        targetIds: batch.targetIds,
        filter: batch.targetType,
        projectKey: settings.projectKey,
        issueType: settings.issueType,
        dispatchMode,
      });

      if (!result.success) {
        launchErrors.push(result.error || "Failed to send to Jira");
        continue;
      }

      startedTasks.push({ taskId: result.taskId, dispatchMode });
    } catch {
      // The request may have reached the server before the RPC failed. An
      // automatic retry could create duplicate issues.
      launchErrors.push(
        "The Jira dispatch status is unknown after a connection error. Check Jira before retrying.",
      );
    }
  }

  const trackedOutcomes = await Promise.all(
    startedTasks.map(async ({ taskId, dispatchMode }) => {
      let trackedTask: TaskTrackingResult<JiraDispatchTaskResult>;
      try {
        trackedTask = await trackAndPollTask<JiraDispatchTaskResult>({
          taskId,
          kind: JIRA_DISPATCH_TASK_KIND,
          meta: buildJiraDispatchTaskMeta({
            integrationId: settings.integrationId,
            projectKey: settings.projectKey,
            issueType: settings.issueType,
            dispatchMode,
          }),
          notifyHandler: options.notifyHandler ?? false,
        });
      } catch {
        return {
          success: false,
          error:
            "Tracking the Jira dispatch failed unexpectedly. Check Jira before retrying.",
        } satisfies JiraTrackedOutcome;
      }

      if (trackedTask.status !== TASK_WATCHER_STATUS.READY) {
        return {
          success: false,
          error: trackedTask.error || "Failed to track Jira issue creation.",
        } satisfies JiraTrackedOutcome;
      }

      const outcome = evaluateJiraDispatchTask("completed", trackedTask.result);
      if (!outcome.success) {
        return {
          success: false,
          error: outcome.error,
          failedFindingIds: outcome.failedFindingIds,
        } satisfies JiraTrackedOutcome;
      }

      return {
        success: true,
        message: outcome.message,
        warning: outcome.warning,
        failedFindingIds: outcome.failedFindingIds,
        successfulCount: getJiraDispatchSuccessCount(trackedTask.result),
      } satisfies JiraTrackedOutcome;
    }),
  );

  const successfulOutcomes = trackedOutcomes.filter(
    (outcome) => outcome.success,
  );
  const successfulIssueCount = successfulOutcomes.reduce(
    (count, outcome) => count + (outcome.successfulCount ?? 0),
    0,
  );
  const successMessage =
    successfulOutcomes.length === 1
      ? successfulOutcomes[0].message
      : successfulOutcomes.length > 1
        ? `${successfulIssueCount} Jira issues were created or updated successfully.`
        : undefined;

  return {
    startedTaskCount: startedTasks.length,
    successfulTaskCount: successfulOutcomes.length,
    successfulIssueCount,
    successMessage,
    warnings: Array.from(
      new Set(
        trackedOutcomes.flatMap((outcome) =>
          outcome.warning ? [outcome.warning] : [],
        ),
      ),
    ),
    errors: Array.from(
      new Set([
        ...trackedOutcomes.flatMap((outcome) =>
          outcome.error ? [outcome.error] : [],
        ),
        ...launchErrors,
      ]),
    ),
    retryBatch: getJiraRetryBatch(
      trackedOutcomes.flatMap((outcome) => outcome.failedFindingIds ?? []),
    ),
  };
}
