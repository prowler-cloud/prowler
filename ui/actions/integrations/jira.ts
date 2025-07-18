"use server";

import { revalidatePath } from "next/cache";

import { auth } from "@/auth.config";
import { handleError } from "@/lib/actions/action-utils";
import { JiraIntegrationFormType } from "@/types/integrations";

export async function createJiraIntegration(
  data: JiraIntegrationFormType,
  providerId: string
): Promise<{
  success: boolean;
  message?: string;
  data?: any;
}> {
  try {
    const session = await auth();
    if (!session?.user?.accessToken) {
      return {
        success: false,
        message: "Authentication required",
      };
    }

    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/integrations/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/vnd.api+json",
          Authorization: `Bearer ${session.user.accessToken}`,
        },
        body: JSON.stringify({
          data: {
            type: "integrations",
            attributes: {
              integration_type: "jira",
              enabled: true,
              config: {
                project_key: data.projectKey,
                issue_type: data.issueType,
                auth_method: data.authMethod,
                ...(data.authMethod === "basic" && {
                  domain: data.domain,
                  user_email: data.userEmail,
                  api_token: data.apiToken,
                }),
                ...(data.authMethod === "oauth2" && {
                  client_id: data.clientId,
                  client_secret: data.clientSecret,
                  redirect_uri: data.redirectUri,
                }),
              },
            },
            relationships: {
              providers: {
                data: [{ type: "providers", id: providerId }],
              },
            },
          },
        }),
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return {
        success: false,
        message: result.errors?.[0]?.detail || "Failed to create Jira integration",
      };
    }

    revalidatePath("/integrations");
    return {
      success: true,
      message: "Jira integration created successfully",
      data: result.data,
    };
  } catch (error) {
    return handleError(error);
  }
}

export async function updateJiraIntegration(
  integrationId: string,
  data: JiraIntegrationFormType
): Promise<{
  success: boolean;
  message?: string;
  data?: any;
}> {
  try {
    const session = await auth();
    if (!session?.user?.accessToken) {
      return {
        success: false,
        message: "Authentication required",
      };
    }

    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/integrations/${integrationId}/`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/vnd.api+json",
          Authorization: `Bearer ${session.user.accessToken}`,
        },
        body: JSON.stringify({
          data: {
            type: "integrations",
            id: integrationId,
            attributes: {
              config: {
                project_key: data.projectKey,
                issue_type: data.issueType,
                auth_method: data.authMethod,
                ...(data.authMethod === "basic" && {
                  domain: data.domain,
                  user_email: data.userEmail,
                  api_token: data.apiToken,
                }),
                ...(data.authMethod === "oauth2" && {
                  client_id: data.clientId,
                  client_secret: data.clientSecret,
                  redirect_uri: data.redirectUri,
                }),
              },
            },
          },
        }),
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return {
        success: false,
        message: result.errors?.[0]?.detail || "Failed to update Jira integration",
      };
    }

    revalidatePath("/integrations");
    return {
      success: true,
      message: "Jira integration updated successfully",
      data: result.data,
    };
  } catch (error) {
    return handleError(error);
  }
}

export async function testJiraConnection(
  data: JiraIntegrationFormType
): Promise<{
  success: boolean;
  message?: string;
}> {
  try {
    const session = await auth();
    if (!session?.user?.accessToken) {
      return {
        success: false,
        message: "Authentication required",
      };
    }

    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/integrations/test-connection/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/vnd.api+json",
          Authorization: `Bearer ${session.user.accessToken}`,
        },
        body: JSON.stringify({
          data: {
            type: "integrations",
            attributes: {
              integration_type: "jira",
              config: {
                project_key: data.projectKey,
                issue_type: data.issueType,
                auth_method: data.authMethod,
                ...(data.authMethod === "basic" && {
                  domain: data.domain,
                  user_email: data.userEmail,
                  api_token: data.apiToken,
                }),
                ...(data.authMethod === "oauth2" && {
                  client_id: data.clientId,
                  client_secret: data.clientSecret,
                  redirect_uri: data.redirectUri,
                }),
              },
            },
          },
        }),
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return {
        success: false,
        message: result.errors?.[0]?.detail || "Failed to test Jira connection",
      };
    }

    return {
      success: true,
      message: "Jira connection test successful",
    };
  } catch (error) {
    return handleError(error);
  }
}

export async function deleteJiraIntegration(
  integrationId: string
): Promise<{
  success: boolean;
  message?: string;
}> {
  try {
    const session = await auth();
    if (!session?.user?.accessToken) {
      return {
        success: false,
        message: "Authentication required",
      };
    }

    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/integrations/${integrationId}/`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${session.user.accessToken}`,
        },
      }
    );

    if (!response.ok) {
      const result = await response.json();
      return {
        success: false,
        message: result.errors?.[0]?.detail || "Failed to delete Jira integration",
      };
    }

    revalidatePath("/integrations");
    return {
      success: true,
      message: "Jira integration deleted successfully",
    };
  } catch (error) {
    return handleError(error);
  }
}

export async function getJiraProjects(
  data: Pick<JiraIntegrationFormType, "authMethod" | "domain" | "userEmail" | "apiToken" | "clientId" | "clientSecret" | "redirectUri">
): Promise<{
  success: boolean;
  message?: string;
  data?: { [key: string]: string };
}> {
  try {
    const session = await auth();
    if (!session?.user?.accessToken) {
      return {
        success: false,
        message: "Authentication required",
      };
    }

    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/integrations/jira/projects/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/vnd.api+json",
          Authorization: `Bearer ${session.user.accessToken}`,
        },
        body: JSON.stringify({
          data: {
            type: "integrations",
            attributes: {
              config: {
                auth_method: data.authMethod,
                ...(data.authMethod === "basic" && {
                  domain: data.domain,
                  user_email: data.userEmail,
                  api_token: data.apiToken,
                }),
                ...(data.authMethod === "oauth2" && {
                  client_id: data.clientId,
                  client_secret: data.clientSecret,
                  redirect_uri: data.redirectUri,
                }),
              },
            },
          },
        }),
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return {
        success: false,
        message: result.errors?.[0]?.detail || "Failed to fetch Jira projects",
      };
    }

    return {
      success: true,
      data: result.data.attributes.projects,
    };
  } catch (error) {
    return handleError(error);
  }
}

export async function getJiraIssueTypes(
  data: Pick<JiraIntegrationFormType, "authMethod" | "domain" | "userEmail" | "apiToken" | "clientId" | "clientSecret" | "redirectUri" | "projectKey">
): Promise<{
  success: boolean;
  message?: string;
  data?: string[];
}> {
  try {
    const session = await auth();
    if (!session?.user?.accessToken) {
      return {
        success: false,
        message: "Authentication required",
      };
    }

    const response = await fetch(
      `${process.env.NEXT_PUBLIC_API_BASE_URL}/integrations/jira/issue-types/`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/vnd.api+json",
          Authorization: `Bearer ${session.user.accessToken}`,
        },
        body: JSON.stringify({
          data: {
            type: "integrations",
            attributes: {
              config: {
                project_key: data.projectKey,
                auth_method: data.authMethod,
                ...(data.authMethod === "basic" && {
                  domain: data.domain,
                  user_email: data.userEmail,
                  api_token: data.apiToken,
                }),
                ...(data.authMethod === "oauth2" && {
                  client_id: data.clientId,
                  client_secret: data.clientSecret,
                  redirect_uri: data.redirectUri,
                }),
              },
            },
          },
        }),
      }
    );

    const result = await response.json();

    if (!response.ok) {
      return {
        success: false,
        message: result.errors?.[0]?.detail || "Failed to fetch Jira issue types",
      };
    }

    return {
      success: true,
      data: result.data.attributes.issue_types,
    };
  } catch (error) {
    return handleError(error);
  }
}