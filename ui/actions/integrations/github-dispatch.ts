"use server";

import { pollTaskUntilSettled } from "@/actions/task/poll";
import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError } from "@/lib/server-actions-helper";
import type { IntegrationProps } from "@/types/integrations";

export interface GitHubDispatchRequest {
  data: {
    type: "integrations-github-dispatches";
    attributes: {
      repository: string;
      labels?: string[];
    };
  };
}

export interface GitHubDispatchResponse {
  data: {
    id: string;
    type: "tasks";
    attributes: {
      state: string;
      result?: {
        created_count?: number;
        failed_count?: number;
        error?: string;
      };
    };
  };
}

export const getGitHubIntegrations = async (): Promise<
  | { success: true; data: IntegrationProps[] }
  | { success: false; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations`);

  // Filter for GitHub integrations only
  url.searchParams.append("filter[integration_type]", "github");

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
      `Unable to fetch GitHub integrations: ${response.statusText}`;
    return { success: false, error: errorMessage };
  } catch (error) {
    const errorResult = handleApiError(error);
    return { success: false, error: errorResult.error || "An error occurred" };
  }
};

export const sendFindingToGitHub = async (
  integrationId: string,
  findingId: string,
  repository: string,
  labels?: string[],
): Promise<
  | { success: true; taskId: string; message: string }
  | { success: false; error: string }
> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(
    `${apiBaseUrl}/integrations/${integrationId}/github/dispatches`,
  );

  // Single finding: use direct filter without array notation
  url.searchParams.append("filter[finding_id]", findingId);

  const payload: GitHubDispatchRequest = {
    data: {
      type: "integrations-github-dispatches",
      attributes: {
        repository: repository,
        labels: labels || [],
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
      const data: GitHubDispatchResponse = await response.json();
      const taskId = data?.data?.id;

      if (taskId) {
        return {
          success: true,
          taskId,
          message: "GitHub issue creation started. Processing...",
        };
      } else {
        return {
          success: false,
          error: "Failed to start GitHub dispatch. No task ID received.",
        };
      }
    }

    const errorData: unknown = await response.json().catch(() => ({}));
    const errorMessage =
      (errorData as { errors?: { detail?: string }[] }).errors?.[0]?.detail ||
      `Unable to send finding to GitHub: ${response.statusText}`;
    return { success: false, error: errorMessage };
  } catch (error) {
    const errorResult = handleApiError(error);
    return { success: false, error: errorResult.error || "An error occurred" };
  }
};

export const pollGitHubDispatchTask = async (
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
  type GitHubTaskResult =
    GitHubDispatchResponse["data"]["attributes"]["result"];
  const githubResult = result as GitHubTaskResult | undefined;

  if (state === "completed") {
    if (!githubResult?.error) {
      return {
        success: true,
        message: "Finding successfully sent to GitHub!",
      };
    }
    return {
      success: false,
      error: githubResult?.error || "Failed to create GitHub issue.",
    };
  }

  if (state === "failed") {
    return { success: false, error: githubResult?.error || "Task failed." };
  }

  return { success: false, error: `Unknown task state: ${state}` };
};
