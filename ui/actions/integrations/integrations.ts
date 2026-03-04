"use server";

import { revalidatePath } from "next/cache";

import { pollTaskUntilSettled } from "@/actions/task/poll";
import { apiBaseUrl, getAuthHeaders, parseStringify } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import { IntegrationType } from "@/types/integrations";
import type { TaskState } from "@/types/tasks";

type TaskStartResponse = {
  data: { id: string; type: "tasks" };
};

type TestConnectionResponse = {
  success: boolean;
  message?: string;
  taskId?: string;
  data?: TaskStartResponse;
  error?: string;
};

export const getIntegrations = async (searchParams?: URLSearchParams) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations`);

  if (searchParams) {
    searchParams.forEach((value, key) => {
      url.searchParams.append(key, value);
    });
  }

  try {
    const response = await fetch(url.toString(), { method: "GET", headers });

    return handleApiResponse(response);
  } catch (error) {
    console.error("Error fetching integrations:", error);
    return { data: [], meta: { pagination: { count: 0 } } };
  }
};

export const createIntegration = async (
  formData: FormData,
): Promise<{ success: string; integrationId?: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations`);

  try {
    const integration_type = formData.get("integration_type") as string;
    const configuration = JSON.parse(
      formData.get("configuration") as string,
    ) as Record<string, unknown>;
    const credentials = JSON.parse(
      formData.get("credentials") as string,
    ) as Record<string, unknown>;
    const providers = JSON.parse(
      formData.get("providers") as string,
    ) as string[];
    const enabled = formData.get("enabled")
      ? JSON.parse(formData.get("enabled") as string)
      : true;

    const integrationData: {
      data: {
        type: "integrations";
        attributes: {
          integration_type: string;
          configuration: Record<string, unknown>;
          credentials: Record<string, unknown>;
          enabled: boolean;
        };
        relationships?: {
          providers: { data: { id: string; type: "providers" }[] };
        };
      };
    } = {
      data: {
        type: "integrations",
        attributes: { integration_type, configuration, credentials, enabled },
      },
    };

    if (Array.isArray(providers) && providers.length > 0) {
      integrationData.data.relationships = {
        providers: {
          data: providers.map((providerId: string) => ({
            id: providerId,
            type: "providers",
          })),
        },
      };
    }

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(integrationData),
    });

    if (response.ok) {
      const responseData = await response.json();
      const integrationId = responseData.data.id;

      // Revalidate the appropriate page based on integration type
      if (integration_type === "amazon_s3") {
        revalidatePath("/integrations/amazon-s3");
      } else if (integration_type === "aws_security_hub") {
        revalidatePath("/integrations/aws-security-hub");
      } else if (integration_type === "jira") {
        revalidatePath("/integrations/jira");
      }

      return {
        success: "Integration created successfully!",
        integrationId,
      };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to create integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateIntegration = async (
  id: string,
  formData: FormData,
): Promise<{ success: string; integrationId?: string } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const integration_type = formData.get("integration_type") as string;
    const configuration = formData.get("configuration")
      ? (JSON.parse(formData.get("configuration") as string) as Record<
          string,
          unknown
        >)
      : undefined;
    const credentials = formData.get("credentials")
      ? (JSON.parse(formData.get("credentials") as string) as Record<
          string,
          unknown
        >)
      : undefined;
    const providers = formData.get("providers")
      ? (JSON.parse(formData.get("providers") as string) as string[])
      : undefined;
    const enabled = formData.get("enabled")
      ? JSON.parse(formData.get("enabled") as string)
      : undefined;

    const integrationData: {
      data: {
        type: "integrations";
        id: string;
        attributes: {
          integration_type: string;
          configuration?: Record<string, unknown>;
          credentials?: Record<string, unknown>;
          enabled?: boolean;
        };
        relationships?: {
          providers: { data: { id: string; type: "providers" }[] };
        };
      };
    } = {
      data: {
        type: "integrations",
        id,
        attributes: { integration_type },
      },
    };

    if (configuration) {
      integrationData.data.attributes.configuration = configuration;
    }

    if (credentials) {
      integrationData.data.attributes.credentials = credentials;
    }

    if (enabled !== undefined) {
      integrationData.data.attributes.enabled = enabled;
    }

    if (providers) {
      integrationData.data.relationships = {
        providers: {
          data: providers.map((providerId: string) => ({
            id: providerId,
            type: "providers",
          })),
        },
      };
    }

    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify(integrationData),
    });

    if (response.ok) {
      // Revalidate the appropriate page based on integration type
      if (integration_type === "amazon_s3") {
        revalidatePath("/integrations/amazon-s3");
      } else if (integration_type === "aws_security_hub") {
        revalidatePath("/integrations/aws-security-hub");
      } else if (integration_type === "jira") {
        revalidatePath("/integrations/jira");
      }

      return {
        success: "Integration updated successfully!",
        integrationId: id,
      };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to update integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteIntegration = async (
  id: string,
  integration_type: IntegrationType,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), { method: "DELETE", headers });

    if (response.ok) {
      // Revalidate the appropriate page based on integration type
      if (integration_type === "amazon_s3") {
        revalidatePath("/integrations/amazon-s3");
      } else if (integration_type === "aws_security_hub") {
        revalidatePath("/integrations/aws-security-hub");
      } else if (integration_type === "jira") {
        revalidatePath("/integrations/jira");
      }

      return { success: "Integration deleted successfully!" };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to delete integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

type ConnectionTaskResult = { connected?: boolean; error?: string | null };

type PollConnectionResult =
  | {
      success: true;
      message: string;
      taskState: TaskState;
      result: ConnectionTaskResult | undefined;
    }
  | {
      success: false;
      message: string;
      taskState?: TaskState;
      result?: ConnectionTaskResult;
    }
  | { error: string };

const pollTaskUntilComplete = async (
  taskId: string,
): Promise<PollConnectionResult> => {
  const settled = await pollTaskUntilSettled<ConnectionTaskResult>(taskId, {
    maxAttempts: 10,
    delayMs: 3000,
  });

  if (!settled.ok) {
    return { error: settled.error };
  }

  const taskState = settled.state;
  const result = settled.result;

  const isSuccessful =
    taskState === "completed" &&
    result?.connected === true &&
    result?.error === null;

  const message = isSuccessful
    ? "Connection test completed successfully."
    : result?.error || "Connection test failed.";

  return { success: isSuccessful, message, taskState, result };
};

export const testIntegrationConnection = async (
  id: string,
  waitForCompletion = true,
): Promise<TestConnectionResponse> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}/connection`);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });

    if (response.ok) {
      const data = await response.json();
      const taskId = data?.data?.id;

      if (taskId) {
        // If waitForCompletion is false, return immediately with task started status
        if (!waitForCompletion) {
          return {
            success: true,
            message:
              "Connection test started. It may take some time to complete.",
            taskId,
            data: parseStringify(data),
          };
        }

        // Poll the task until completion
        const pollResult = await pollTaskUntilComplete(taskId);

        revalidatePath("/integrations/amazon-s3");
        revalidatePath("/integrations/aws-security-hub");
        revalidatePath("/integrations/jira");

        if ("error" in pollResult) {
          return { success: false, error: pollResult.error };
        }

        if (pollResult.success) {
          return {
            success: true,
            message:
              pollResult.message || "Connection test completed successfully!",
            data: parseStringify(data),
          };
        } else {
          return {
            success: false,
            error: pollResult.message || "Connection test failed.",
          };
        }
      } else {
        return {
          success: false,
          error: "Failed to start connection test. No task ID received.",
        };
      }
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to test integration connection: ${response.statusText}`;
    return { success: false, error: errorMessage };
  } catch (error) {
    const handled = handleApiError(error);
    return { success: false, error: handled.error };
  }
};

export const pollConnectionTestStatus = async (
  taskId: string,
): Promise<TestConnectionResponse> => {
  try {
    const pollResult = await pollTaskUntilComplete(taskId);

    revalidatePath("/integrations/amazon-s3");
    revalidatePath("/integrations/aws-security-hub");
    revalidatePath("/integrations/jira");

    if ("error" in pollResult) {
      return { success: false, error: pollResult.error };
    }

    if (pollResult.success) {
      return {
        success: true,
        message:
          pollResult.message || "Connection test completed successfully!",
      };
    } else {
      return {
        success: false,
        error: pollResult.message || "Connection test failed.",
      };
    }
  } catch (_error) {
    return { success: false, error: "Failed to check connection test status." };
  }
};
