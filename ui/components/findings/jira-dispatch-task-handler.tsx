"use client";

import { toast, ToastAction } from "@/components/shadcn/toast";
import {
  executeJiraDispatchBatches,
  getJiraRetryBatch,
} from "@/lib/jira-dispatch-execution";
import { evaluateJiraDispatchTask } from "@/lib/jira-dispatch-result";
import { parseJiraDispatchTaskMeta } from "@/lib/jira-dispatch-task";
import type { TaskKindHandler, WatchedTask } from "@/store/task-watcher/store";
import {
  JIRA_DISPATCH_MODE,
  type JiraDispatchTaskResult,
} from "@/types/integrations";

const retryFailedFindings = async (
  task: WatchedTask,
  failedFindingIds: string[],
): Promise<void> => {
  const meta = parseJiraDispatchTaskMeta(task);
  if (!meta) {
    toast({
      variant: "destructive",
      title: "Jira retry failed",
      description: "The original Jira dispatch configuration is unavailable.",
    });
    return;
  }

  const retryBatch = getJiraRetryBatch(failedFindingIds);
  if (!retryBatch) return;

  try {
    toast({
      title: "Retry started",
      description: `Retrying ${failedFindingIds.length} failed Finding${failedFindingIds.length === 1 ? "" : "s"}.`,
    });

    const result = await executeJiraDispatchBatches(
      [retryBatch],
      {
        integrationId: meta.integrationId,
        projectKey: meta.projectKey,
        issueType: meta.issueType,
        dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
      },
      { notifyHandler: true },
    );
    if (result.startedTaskCount === 0 && result.errors.length > 0) {
      toast({
        variant: "destructive",
        title: "Jira retry failed",
        description: result.errors.join(" "),
      });
    }
  } catch {
    toast({
      variant: "destructive",
      title: "Jira retry failed",
      description: "The retry could not be started. Try again later.",
    });
  }
};

const buildRetryAction = (task: WatchedTask, failedFindingIds?: string[]) =>
  failedFindingIds?.length ? (
    <ToastAction
      altText="Retry failed Findings"
      onClick={() => retryFailedFindings(task, failedFindingIds)}
    >
      Retry failed
    </ToastAction>
  ) : undefined;

export const jiraDispatchTaskHandler: TaskKindHandler = {
  onReady: (task) => {
    const outcome = evaluateJiraDispatchTask(
      "completed",
      task.result as JiraDispatchTaskResult | undefined,
    );

    if (!outcome.success) {
      toast({
        variant: "destructive",
        title: "Jira dispatch failed",
        description: outcome.error,
        action: buildRetryAction(task, outcome.failedFindingIds),
      });
      return;
    }

    toast({
      title: outcome.warning ? "Jira dispatch partially completed" : "Success!",
      description: outcome.warning ?? outcome.message,
      action: buildRetryAction(task, outcome.failedFindingIds),
    });
  },
  onError: (task) => {
    toast({
      variant: "destructive",
      title: "Jira dispatch failed",
      description: task.error || "The Jira dispatch task failed unexpectedly.",
    });
  },
};
