"use client";

import { sendJiraDispatch } from "@/actions/integrations/jira-dispatch";
import { toast, ToastAction } from "@/components/shadcn/toast";
import { evaluateJiraDispatchTask } from "@/lib/jira-dispatch-result";
import {
  buildJiraDispatchTaskMeta,
  parseJiraDispatchTaskMeta,
} from "@/lib/jira-dispatch-task";
import {
  type TaskKindHandler,
  trackAndPollTask,
  type WatchedTask,
} from "@/store/task-watcher/store";
import {
  JIRA_DISPATCH_MODE,
  JIRA_DISPATCH_TARGET,
  JIRA_DISPATCH_TASK_KIND,
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

  try {
    const response = await sendJiraDispatch({
      integrationId: meta.integrationId,
      targetIds: failedFindingIds,
      filter: JIRA_DISPATCH_TARGET.FINDING_ID,
      projectKey: meta.projectKey,
      issueType: meta.issueType,
      dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
    });

    if (!response.success) {
      toast({
        variant: "destructive",
        title: "Jira retry failed",
        description: response.error,
      });
      return;
    }

    toast({
      title: "Retry started",
      description: `Retrying ${failedFindingIds.length} failed Finding${failedFindingIds.length === 1 ? "" : "s"}.`,
    });

    await trackAndPollTask<JiraDispatchTaskResult>({
      taskId: response.taskId,
      kind: JIRA_DISPATCH_TASK_KIND,
      meta: buildJiraDispatchTaskMeta({
        ...meta,
        dispatchMode: JIRA_DISPATCH_MODE.INDIVIDUAL,
      }),
    });
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
