"use server";

import { pollTaskUntilSettled } from "@/actions/task/poll";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";
import type {
  IntegrationProps,
  JiraDispatchRequest,
  JiraDispatchResponse,
} from "@/types/integrations";

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
  _issueType: string,
): Promise<
  | { success: true; taskId: string; message: string }
  | { success: false; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(
    `${apiBaseUrl}/integrations/${integrationId}/jira/dispatches`,
  );

  // Single finding: use direct filter without array notation
  url.searchParams.append("filter[finding_id]", findingId);

  const payload: JiraDispatchRequest = {
    data: {
      type: "integrations-jira-dispatches",
      attributes: {
        project_key: projectKey,
        // Temporarily hardcode to "Task" regardless of the provided value
        issue_type: "Task",
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
    maxAttempts: 10,
    delayMs: 2000,
  });
  if (!res.ok) {
    return { success: false, error: res.error };
  }
  const { state, result } = res;
  type JiraTaskResult = JiraDispatchResponse["data"]["attributes"]["result"];
  const jiraResult = result as JiraTaskResult | undefined;

  if (state === "completed") {
    if (!jiraResult?.error) {
      return { success: true, message: "Finding successfully sent to Jira!" };
    }
    return {
      success: false,
      error: jiraResult?.error || "Failed to create Jira issue.",
    };
  }

  if (state === "failed") {
    return { success: false, error: jiraResult?.error || "Task failed." };
  }

  return { success: false, error: `Unknown task state: ${state}` };
};
