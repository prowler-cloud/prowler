"use server";

import { revalidatePath } from "next/cache";

import {
  apiBaseUrl,
  getAuthHeaders,
  handleApiError,
  parseStringify,
} from "@/lib";

import { getTask } from "../task";

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

    if (response.ok) {
      const data = await response.json();
      return parseStringify(data);
    }

    console.error(`Failed to fetch integrations: ${response.statusText}`);
    return { data: [], meta: { pagination: { count: 0 } } };
  } catch (error) {
    console.error("Error fetching integrations:", error);
    return { data: [], meta: { pagination: { count: 0 } } };
  }
};

export const getIntegration = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), { method: "GET", headers });

    if (response.ok) {
      const data = await response.json();
      return parseStringify(data);
    }

    console.error(`Failed to fetch integration: ${response.statusText}`);
    return null;
  } catch (error) {
    console.error("Error fetching integration:", error);
    return null;
  }
};

export const createIntegration = async (
  formData: FormData,
): Promise<{ success: string; testConnection?: any } | { error: string }> => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations`);

  try {
    const integration_type = formData.get("integration_type") as string;
    const configuration = JSON.parse(formData.get("configuration") as string);
    const credentials = JSON.parse(formData.get("credentials") as string);
    const providers = JSON.parse(formData.get("providers") as string);
    const enabled = formData.get("enabled")
      ? JSON.parse(formData.get("enabled") as string)
      : true;

    const integrationData = {
      data: {
        type: "integrations",
        attributes: { integration_type, configuration, credentials, enabled },
        relationships: {
          providers: {
            data: providers.map((providerId: string) => ({
              id: providerId,
              type: "providers",
            })),
          },
        },
      },
    };

    console.log("integrationData", JSON.stringify(integrationData, null, 2));

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(integrationData),
    });

    if (response.ok) {
      const responseData = await response.json();
      const integrationId = responseData.data.id;

      const testResult = await testIntegrationConnection(integrationId);

      return {
        success: "Integration created successfully!",
        testConnection: testResult,
      };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to create S3 integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateIntegration = async (id: string, formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const integration_type = formData.get("integration_type") as string;
    const configuration = formData.get("configuration")
      ? JSON.parse(formData.get("configuration") as string)
      : undefined;
    const credentials = formData.get("credentials")
      ? JSON.parse(formData.get("credentials") as string)
      : undefined;
    const providers = formData.get("providers")
      ? JSON.parse(formData.get("providers") as string)
      : undefined;
    const enabled = formData.get("enabled")
      ? JSON.parse(formData.get("enabled") as string)
      : undefined;

    const integrationData: any = {
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
      revalidatePath("/integrations/s3");

      // Only test connection if credentials or configuration were updated
      if (credentials || configuration) {
        const testResult = await testIntegrationConnection(id);
        return {
          success: "Integration updated successfully!",
          testConnection: testResult,
        };
      } else {
        return {
          success: "Integration updated successfully!",
        };
      }
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to update S3 integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteIntegration = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}`);

  try {
    const response = await fetch(url.toString(), { method: "DELETE", headers });

    if (response.ok) {
      revalidatePath("/integrations/s3");
      return { success: "Integration deleted successfully!" };
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to delete S3 integration: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};

const pollTaskUntilComplete = async (taskId: string): Promise<any> => {
  const maxAttempts = 10;
  let attempts = 0;

  while (attempts < maxAttempts) {
    try {
      const taskResponse = await getTask(taskId);

      if (taskResponse.error) {
        return { error: taskResponse.error };
      }

      const task = taskResponse.data;
      const taskState = task?.attributes?.state;

      // Continue polling while task is executing
      if (taskState === "executing") {
        await new Promise((resolve) => setTimeout(resolve, 3000));
        attempts++;
        continue;
      }

      const result = task?.attributes?.result;
      const isSuccessful =
        taskState === "completed" &&
        result?.connected === true &&
        result?.error === null;

      let message;
      if (isSuccessful) {
        message = "Connection test completed successfully.";
      } else {
        message = result?.error || "Connection test failed.";
      }

      return {
        success: isSuccessful,
        message,
        taskState,
        result,
      };
    } catch (error) {
      return { error: "Failed to monitor connection test." };
    }
  }

  return { error: "Connection test timeout. Test took too long to complete." };
};

export const testIntegrationConnection = async (id: string) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/integrations/${id}/connection`);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });

    if (response.ok) {
      const data = await response.json();
      const taskId = data?.data?.id;

      if (taskId) {
        // Poll the task until completion
        const pollResult = await pollTaskUntilComplete(taskId);

        revalidatePath("/integrations/s3");

        if (pollResult.error) {
          return { error: pollResult.error };
        }

        if (pollResult.success) {
          return {
            success: "Connection test completed successfully!",
            message: pollResult.message,
            data: parseStringify(data),
          };
        } else {
          return {
            error: pollResult.message || "Connection test failed.",
          };
        }
      } else {
        return {
          error: "Failed to start connection test. No task ID received.",
        };
      }
    }

    const errorData = await response.json().catch(() => ({}));
    const errorMessage =
      errorData.errors?.[0]?.detail ||
      `Unable to test S3 integration connection: ${response.statusText}`;
    return { error: errorMessage };
  } catch (error) {
    return handleApiError(error);
  }
};
