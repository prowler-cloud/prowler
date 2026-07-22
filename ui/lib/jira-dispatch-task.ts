import type { WatchedTask } from "@/store/task-watcher/store";
import {
  JIRA_DISPATCH_MODE,
  type JiraDispatchMode,
} from "@/types/integrations";

export interface JiraDispatchTaskMeta {
  integrationId: string;
  projectKey: string;
  issueType: string;
  dispatchMode: JiraDispatchMode;
}

export const buildJiraDispatchTaskMeta = ({
  integrationId,
  projectKey,
  issueType,
  dispatchMode,
}: JiraDispatchTaskMeta): Record<string, string> => ({
  integrationId,
  projectKey,
  issueType,
  dispatchMode,
});

export const parseJiraDispatchTaskMeta = (
  task: WatchedTask,
): JiraDispatchTaskMeta | null => {
  const { integrationId, projectKey, issueType, dispatchMode } = task.meta;
  if (
    !integrationId ||
    !projectKey ||
    !issueType ||
    (dispatchMode !== JIRA_DISPATCH_MODE.GROUPED &&
      dispatchMode !== JIRA_DISPATCH_MODE.INDIVIDUAL)
  ) {
    return null;
  }

  return {
    integrationId,
    projectKey,
    issueType,
    dispatchMode,
  };
};
