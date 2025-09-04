"use server";

import { apiBaseUrl, getAuthHeaders, handleApiError } from "@/lib";

export const getJiraIntegrations = async (): Promise<
  { success: true; data: any[] } | { success: false; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations`);

  // Filter for Jira integrations only
  url.searchParams.append("filter[integration_type]", "jira");

  try {
    const response = await fetch(url.toString(), { method: "GET", headers });

    if (response.ok) {
      const data = await response.json();
      // Filter for enabled integrations on the client side
      const enabledIntegrations = (data.data || []).filter(
        (integration: any) => integration.attributes.enabled === true,
      );
      return { success: true, data: enabledIntegrations };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
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
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(
    `${apiBaseUrl}/integrations/${integrationId}/jira/dispatches`,
  );

  // Single finding: use direct filter without array notation
  url.searchParams.append("filter[finding_id]", findingId);

  console.log(url.toString());

  const payload = {
    data: {
      type: "integrations-jira-dispatches",
      attributes: {
        project_key: projectKey,
        issue_type: issueType,
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
      const data = await response.json();
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

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
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
  | { success: true; message: string; issueUrl?: string; issueKey?: string }
  | { success: false; error: string }
> => {
  const { getTask } = await import("@/actions/task");
  const maxAttempts = 10;
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      const taskResponse = await getTask(taskId);

      if (taskResponse.error) {
        return { success: false, error: taskResponse.error };
      }

      const task = taskResponse.data;
      const taskState = task?.attributes?.state;

      // Continue polling while task is executing or available
      if (taskState === "executing" || taskState === "available") {
        await new Promise((resolve) => setTimeout(resolve, 2000));
        attempts++;
        continue;
      }

      // Task completed
      if (taskState === "completed") {
        const result = task?.attributes?.result;
        if (result?.success) {
          return {
            success: true,
            message: result.message || "Finding successfully sent to Jira!",
            issueUrl: result.issue_url,
            issueKey: result.issue_key,
          };
        } else {
          return {
            success: false,
            error: result?.error || "Failed to create Jira issue.",
          };
        }
      }

      // Task failed
      if (taskState === "failed") {
        return {
          success: false,
          error: task?.attributes?.result?.error || "Task failed.",
        };
      }

      // Unknown state
      return {
        success: false,
        error: `Unknown task state: ${taskState}`,
      };
    } catch (error) {
      return { success: false, error: "Failed to check task status." };
    }
  }

  return {
    success: false,
    error: "Task timeout. Please check Jira for the issue.",
  };
};
