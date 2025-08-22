"use server";

import { revalidatePath } from "next/cache";
import { redirect } from "next/navigation";
import yaml from "js-yaml";

import {
  apiBaseUrl,
  getAuthHeaders,
  getErrorMessage,
  getFormValue,
  handleApiError,
  handleApiResponse,
  parseStringify,
  wait,
} from "@/lib";
import { buildSecretConfig } from "@/lib/provider-credentials/build-crendentials";
import { ProviderCredentialFields } from "@/lib/provider-credentials/provider-credential-fields";
import { ProvidersApiResponse, ProviderType } from "@/types/providers";

export const getProviders = async ({
  page = 1,
  query = "",
  sort = "",
  filters = {},
  pageSize = 10,
}): Promise<ProvidersApiResponse | undefined> => {
  const headers = await getAuthHeaders({ contentType: false });

  if (isNaN(Number(page)) || page < 1) redirect("/providers");

  const url = new URL(`${apiBaseUrl}/providers?include=provider_groups`);

  if (page) url.searchParams.append("page[number]", page.toString());
  if (pageSize) url.searchParams.append("page[size]", pageSize.toString());
  if (query) url.searchParams.append("filter[search]", query);
  if (sort) url.searchParams.append("sort", sort);

  // Handle multiple filters
  Object.entries(filters).forEach(([key, value]) => {
    if (key !== "filter[search]") {
      url.searchParams.append(key, String(value));
    }
  });

  try {
    const providers = await fetch(url.toString(), {
      headers,
    });
    const data = await providers.json();
    const parsedData = parseStringify(data);
    revalidatePath("/providers");
    return parsedData;
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error fetching providers:", error);
    return undefined;
  }
};

export const getProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerId = formData.get("id");

  const url = new URL(`${apiBaseUrl}/providers/${providerId}`);

  try {
    const providers = await fetch(url.toString(), {
      headers,
    });
    const data = await providers.json();
    const parsedData = parseStringify(data);
    return parsedData;
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

export const updateProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);
  const providerAlias = formData.get(ProviderCredentialFields.PROVIDER_ALIAS);
  const url = new URL(`${apiBaseUrl}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "providers",
          id: providerId,
          attributes: { alias: providerAlias },
        },
      }),
    });

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const addProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });

  const providerType = formData.get("providerType") as ProviderType;
  const providerUid = formData.get("providerUid") as string;
  const providerAlias = formData.get("providerAlias") as string;

  const url = new URL(`${apiBaseUrl}/providers`);

  try {
    const bodyData = {
      data: {
        type: "providers",
        attributes: {
          provider: providerType,
          uid: providerUid,
          ...(providerAlias?.trim() && { alias: providerAlias.trim() }),
        },
      },
    };

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify(bodyData),
    });

    const data = await response.json();
    revalidatePath("/providers");
    return parseStringify(data);
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error(error);
    return {
      error: getErrorMessage(error),
    };
  }
};

export const addCredentialsProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/providers/secrets`);

  const providerId = getFormValue(
    formData,
    ProviderCredentialFields.PROVIDER_ID,
  );
  const providerType = getFormValue(
    formData,
    ProviderCredentialFields.PROVIDER_TYPE,
  ) as ProviderType;

  try {
    const { secretType, secret } = buildSecretConfig(formData, providerType);

    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "provider-secrets",
          attributes: { secret_type: secretType, secret },
          relationships: {
            provider: {
              data: { id: providerId, type: "providers" },
            },
          },
        },
      }),
    });

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const updateCredentialsProvider = async (
  credentialsId: string,
  formData: FormData,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/providers/secrets/${credentialsId}`);
  const providerType = getFormValue(
    formData,
    ProviderCredentialFields.PROVIDER_TYPE,
  ) as ProviderType;

  try {
    const { secretType, secret } = buildSecretConfig(formData, providerType);
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "provider-secrets",
          id: credentialsId,
          attributes: { secret_type: secretType, secret },
        },
      }),
    });

    if (!response.ok) {
      const data = await response.json();
      return parseStringify(data); // Return API errors for UI handling
    }

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const checkConnectionProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);
  const url = new URL(`${apiBaseUrl}/providers/${providerId}/connection`);

  try {
    const response = await fetch(url.toString(), { method: "POST", headers });
    await wait(2000);
    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

export const deleteCredentials = async (secretId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  if (!secretId) {
    return { error: "Secret ID is required" };
  }

  const url = new URL(`${apiBaseUrl}/providers/secrets/${secretId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(
          errorData?.message || "Failed to delete the credentials",
        );
      } catch {
        throw new Error("Failed to delete the credentials");
      }
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/providers");
    return data || { success: true };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error deleting credentials:", error);
    return { error: getErrorMessage(error) };
  }
};

export const deleteProvider = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: false });
  const providerId = formData.get(ProviderCredentialFields.PROVIDER_ID);

  if (!providerId) {
    return { error: "Provider ID is required" };
  }

  const url = new URL(`${apiBaseUrl}/providers/${providerId}`);

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    if (!response.ok) {
      try {
        const errorData = await response.json();
        throw new Error(errorData?.message || "Failed to delete the provider");
      } catch {
        throw new Error("Failed to delete the provider");
      }
    }

    let data = null;
    if (response.status !== 204) {
      data = await response.json();
    }

    revalidatePath("/providers");
    return data || { success: true };
  } catch (error) {
    // eslint-disable-next-line no-console
    console.error("Error deleting provider:", error);
    return { error: getErrorMessage(error) };
  }
};

// Bulk provider import functionality
export const bulkImportProviders = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const yamlContent = formData.get("yamlContent") as string;

  if (!yamlContent) {
    return { error: "YAML content is required" };
  }

  try {
    
    const providers = yaml.load(yamlContent);

    if (!Array.isArray(providers)) {
      return { error: "YAML content must be an array of provider configurations" };
    }

    const results = [];
    const errors = [];

    for (let i = 0; i < providers.length; i++) {
      const provider = providers[i];
      const providerNum = i + 1;

      try {
        // Step 1: Create provider
        const providerResponse = await fetch(`${apiBaseUrl}/providers`, {
          method: "POST",
          headers,
          body: JSON.stringify({
            data: {
              type: "providers",
              attributes: {
                provider: provider.provider,
                uid: provider.uid,
                ...(provider.alias && { alias: provider.alias }),
              },
            },
          }),
        });

        const providerData = await providerResponse.json();
        
        if (!providerResponse.ok) {
          errors.push({
            provider: providerNum,
            step: "provider_creation",
            error: providerData,
          });
          continue;
        }

        const providerId = providerData.data.id;
        results.push({
          provider: providerNum,
          providerId,
          providerData,
        });

        // Step 2: Create credentials if provided
        if (provider.auth_method && provider.credentials) {
          try {
            const { secretType, secret } = buildCredentialsFromYaml(provider);
            
            const secretResponse = await fetch(`${apiBaseUrl}/providers/secrets`, {
              method: "POST",
              headers,
              body: JSON.stringify({
                data: {
                  type: "provider-secrets",
                  attributes: { 
                    secret_type: secretType, 
                    secret,
                    name: provider.alias || `${provider.provider}-${provider.uid}`,
                  },
                  relationships: {
                    provider: {
                      data: { id: providerId, type: "providers" },
                    },
                  },
                },
              }),
            });

            const secretData = await secretResponse.json();
            
            if (!secretResponse.ok) {
              errors.push({
                provider: providerNum,
                step: "credentials_creation",
                error: secretData,
              });
            } else {
              results[results.length - 1].secretData = secretData;
            }
          } catch (credError) {
            errors.push({
              provider: providerNum,
              step: "credentials_processing",
              error: getErrorMessage(credError),
            });
          }
        }
      } catch (error) {
        errors.push({
          provider: providerNum,
          step: "general",
          error: getErrorMessage(error),
        });
      }
    }

    revalidatePath("/providers");
    return parseStringify({
      success: true,
      results,
      errors,
      summary: {
        total: providers.length,
        successful: results.length,
        failed: errors.length,
      },
    });
  } catch (error) {
    return {
      error: getErrorMessage(error),
    };
  }
};

// Helper function to build credentials from YAML provider config
function buildCredentialsFromYaml(provider: any) {
  const { provider: providerType, auth_method: authMethod, credentials } = provider;
  
  let secretType = "static";
  let secret: any = {};

  if (providerType === "aws") {
    if (authMethod === "role") {
      secretType = "role";
      secret = {
        role_arn: credentials.role_arn,
        external_id: credentials.external_id,
        ...(credentials.session_name && { role_session_name: credentials.session_name }),
        ...(credentials.duration_seconds && { session_duration: credentials.duration_seconds }),
        ...(credentials.access_key_id && { aws_access_key_id: credentials.access_key_id }),
        ...(credentials.secret_access_key && { aws_secret_access_key: credentials.secret_access_key }),
        ...(credentials.session_token && { aws_session_token: credentials.session_token }),
      };
    } else if (authMethod === "credentials") {
      secretType = "static";
      secret = {
        aws_access_key_id: credentials.access_key_id,
        aws_secret_access_key: credentials.secret_access_key,
        ...(credentials.session_token && { aws_session_token: credentials.session_token }),
      };
    }
  } else if (providerType === "azure") {
    if (authMethod === "service_principal") {
      secretType = "static";
      secret = {
        tenant_id: credentials.tenant_id,
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
      };
    }
  } else if (providerType === "gcp") {
    if (authMethod === "service_account" || authMethod === "service_account_json") {
      secretType = "service_account";
      if (credentials.inline_json) {
        secret = { service_account_key: credentials.inline_json };
      } else if (credentials.service_account_key_json_path) {
        // For file paths, we can't read the file in the browser
        throw new Error("File path credentials are not supported in bulk import. Use inline_json instead.");
      }
    } else if (authMethod === "oauth2" || authMethod === "adc") {
      secretType = "static";
      secret = {
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
        refresh_token: credentials.refresh_token,
      };
    }
  } else if (providerType === "kubernetes") {
    if (authMethod === "kubeconfig") {
      secretType = "static";
      secret = {
        kubeconfig_content: credentials.kubeconfig_inline || credentials.kubeconfig_content,
      };
    }
  } else if (providerType === "m365") {
    if (authMethod === "service_principal") {
      secretType = "static";
      secret = {
        tenant_id: credentials.tenant_id,
        client_id: credentials.client_id,
        client_secret: credentials.client_secret,
        ...(credentials.username && { user: credentials.username }),
        ...(credentials.password && { password: credentials.password }),
      };
    }
  } else if (providerType === "github") {
    if (authMethod === "personal_access_token") {
      secretType = "static";
      secret = { personal_access_token: credentials.token };
    } else if (authMethod === "oauth_app_token") {
      secretType = "static";
      secret = { oauth_app_token: credentials.oauth_token };
    } else if (authMethod === "github_app") {
      secretType = "static";
      secret = {
        github_app_id: parseInt(credentials.app_id, 10),
        github_app_key_content: credentials.private_key_inline || credentials.private_key,
      };
    }
  }

  return { secretType, secret };
}
