"use server";

import { pollTaskUntilSettled } from "@/actions/task/poll";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";
import type {
  IntegrationProps,
  JiraDispatchMode,
  JiraDispatchRequest,
  JiraDispatchResponse,
  JiraDispatchTarget,
} from "@/types/integrations";
import { JIRA_DISPATCH_MODE, JIRA_DISPATCH_TARGET } from "@/types/integrations";

type JiraTaskResult = NonNullable<
  JiraDispatchResponse["data"]["attributes"]["result"]
>;

interface JiraDispatchInput {
  integrationId: string;
  targetIds: string[];
  filter: JiraDispatchTarget;
  projectKey: string;
  issueType: string;
  dispatchMode?: JiraDispatchMode;
}

const getArrayCount = (value: unknown[] | undefined) =>
  Array.isArray(value) ? value.length : 0;

const getJiraDispatchFailedCount = (result: JiraTaskResult | undefined) => {
  if (!result) return 0;
  return Math.max(
    result.failed_count ?? 0,
    getArrayCount(result.failed_groups),
    getArrayCount(result.failed_batches),
  );
};

const getJiraDispatchSuccessCount = (result: JiraTaskResult | undefined) => {
  if (!result) return 0;
  return Math.max(
    result.successful_count ?? 0,
    result.created_count ?? 0,
    result.updated_count ?? 0,
    getArrayCount(result.created_issues),
    getArrayCount(result.updated_issues),
    result.issue_key || result.issue_url ? 1 : 0,
  );
};

const buildJiraDispatchFailureMessage = (
  result: JiraTaskResult | undefined,
  failedCount: number,
) => {
  if (result?.error) return result.error;

  const createdCount = result?.created_count ?? 0;
  const updatedCount = result?.updated_count ?? 0;
  const successCount = createdCount + updatedCount;
  return `Jira dispatch completed with ${failedCount} failed and ${successCount} created/updated issue${successCount === 1 ? "" : "s"}.`;
};

export const getJiraIssueTypes = async (
  integrationId: string,
  projectKey: string,
): Promise<
  { success: true; issueTypes: string[] } | { success: false; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(
    `${apiBaseUrl}/integrations/${integrationId}/jira/issue_types`,
  );
  url.searchParams.append("project_key", projectKey);

  try {
    const response = await fetch(url.toString(), { method: "GET", headers });

    if (response.ok) {
      const data: {
        data: { type: string; attributes: { issue_types: string[] } };
      } = await response.json();
      return {
        success: true,
        issueTypes: data.data?.attributes?.issue_types ?? [],
      };
    }

    const errorData: unknown = await response.json().catch(() => ({}));
    const errorMessage =
      (errorData as { errors?: { detail?: string }[] }).errors?.[0]?.detail ||
      `Unable to fetch issue types: ${response.statusText}`;
    return { success: false, error: errorMessage };
  } catch (error) {
    const errorResult = handleApiError(error);
    return { success: false, error: errorResult.error || "An error occurred" };
  }
};

export const getJiraIntegrations = async (): Promise<
  | { success: true; data: IntegrationProps[] }
  | { success: false; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations`);

  // Filter for Jira integrations only
  url.searchParams.append("filter[integration_type]", "jira");

  try {
    const response = await fetch(url.toString(), { method: "GET", headers });

    if (response.ok) {
      const data: { data: IntegrationProps[] } = await response.json();
      // Filter for enabled integrations on the client side
      const enabledIntegrations = (data.data || []).filter(
        (integration: IntegrationProps) =>
          integration.attributes.enabled === true,
      );
      return { success: true, data: enabledIntegrations };
    }

    const errorData: unknown = await response.json().catch(() => ({}));
    const errorMessage =
      (errorData as { errors?: { detail?: string }[] }).errors?.[0]?.detail ||
      `Unable to fetch Jira integrations: ${response.statusText}`;
    return { success: false, error: errorMessage };
  } catch (error) {
    const errorResult = handleApiError(error);
    return { success: false, error: errorResult.error || "An error occurred" };
  }
};

export const sendFindingToJira = async (
  integrationId: string,
  findingId: string,
  projectKey: string,
  issueType: string,
): Promise<
  | { success: true; taskId: string; message: string }
  | { success: false; error: string }
> => {
  return sendJiraDispatch({
    integrationId,
    targetIds: [findingId],
    filter: JIRA_DISPATCH_TARGET.FINDING_ID,
    projectKey,
    issueType,
  });
};

export const sendJiraDispatch = async ({
  integrationId,
  targetIds,
  filter,
  projectKey,
  issueType,
  dispatchMode = JIRA_DISPATCH_MODE.INDIVIDUAL,
}: JiraDispatchInput): Promise<
  | { success: true; taskId: string; message: string }
  | { success: false; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(
    `${apiBaseUrl}/integrations/${integrationId}/jira/dispatches`,
  );

  if (targetIds.length === 1) {
    url.searchParams.append(`filter[${filter}]`, targetIds[0]);
  } else {
    url.searchParams.append(`filter[${filter}__in]`, targetIds.join(","));
  }

  const payload: JiraDispatchRequest = {
    data: {
      type: "integrations-jira-dispatches",
      attributes: {
        project_key: projectKey,
        issue_type: issueType,
        dispatch_mode: dispatchMode,
      },
    },
  };

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
    });

    if (response.ok) {
      const data: JiraDispatchResponse = await response.json();
      const taskId = data?.data?.id;

      if (taskId) {
        return {
          success: true,
          taskId,
          message: "Jira issue creation started. Processing...",
        };
      } else {
        return {
          success: false,
          error: "Failed to start Jira dispatch. No task ID received.",
        };
      }
    }

    const errorData: unknown = await response.json().catch(() => ({}));
    const errorMessage =
      (errorData as { errors?: { detail?: string }[] }).errors?.[0]?.detail ||
      `Unable to send finding to Jira: ${response.statusText}`;
    return { success: false, error: errorMessage };
  } catch (error) {
    const errorResult = handleApiError(error);
    return { success: false, error: errorResult.error || "An error occurred" };
  }
};

export const pollJiraDispatchTask = async (
  taskId: string,
): Promise<
  { success: true; message: string } | { success: false; error: string }
> => {
  const res = await pollTaskUntilSettled(taskId, {
    maxAttempts: 5,
    delayMs: 2000,
  });
  if (!res.ok) {
    return { success: false, error: res.error };
  }
  const { state, result } = res;
  const jiraResult = (result ?? undefined) as JiraTaskResult | undefined;

  if (state === "completed") {
    const failedCount = getJiraDispatchFailedCount(jiraResult);
    if (failedCount > 0) {
      return {
        success: false,
        error: buildJiraDispatchFailureMessage(jiraResult, failedCount),
      };
    }

    if (jiraResult?.success === false || jiraResult?.error) {
      return {
        success: false,
        error: jiraResult?.error || "Failed to create Jira issue.",
      };
    }

    if (!jiraResult || getJiraDispatchSuccessCount(jiraResult) === 0) {
      return {
        success: false,
        error:
          "Jira dispatch completed but did not create or update any issues.",
      };
    }

    return { success: true, message: "Finding successfully sent to Jira!" };
  }

  if (state === "failed") {
    return { success: false, error: jiraResult?.error || "Task failed." };
  }

  return { success: false, error: `Unknown task state: ${state}` };
};
