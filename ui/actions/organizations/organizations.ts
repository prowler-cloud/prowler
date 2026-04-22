"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  OrganizationListResponse,
  OrganizationUnitListResponse,
} from "@/types";

const PATH_IDENTIFIER_PATTERN = /^[A-Za-z0-9_-]+$/;

type PathIdentifierValidationResult = { value: string } | { error: string };

function validatePathIdentifier(
  value: string | null | undefined,
  requiredError: string,
  invalidError: string,
): PathIdentifierValidationResult {
  const normalizedValue = value?.trim();

  if (!normalizedValue) {
    return { error: requiredError };
  }

  if (!PATH_IDENTIFIER_PATTERN.test(normalizedValue)) {
    return { error: invalidError };
  }

  return { value: normalizedValue };
}

function hasActionError(result: unknown): result is { error: unknown } {
  return Boolean(
    result &&
      typeof result === "object" &&
      "error" in (result as Record<string, unknown>) &&
      (result as Record<string, unknown>).error !== null &&
      (result as Record<string, unknown>).error !== undefined,
  );
}

async function fetchOptionalCollection<T extends { data: unknown[] }>(
  url: URL,
): Promise<T> {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(url.toString(), { headers });

    if (!response.ok) {
      return { data: [] } as unknown as T;
    }

    return (await handleApiResponse(response)) as T;
  } catch {
    return { data: [] } as unknown as T;
  }
}

/**
 * Creates an AWS Organization resource.
 * POST /api/v1/organizations
 */
export const createOrganization = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/organizations`);

  const name = formData.get("name") as string;
  const externalId = formData.get("externalId") as string;

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "organizations",
          attributes: {
            name,
            org_type: "aws",
            external_id: externalId,
          },
        },
      }),
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Updates an AWS Organization's name.
 * PATCH /api/v1/organizations/{id}
 */
export const updateOrganizationName = async (
  organizationId: string,
  name: string,
) => {
  const trimmed = name.trim();
  if (!trimmed) {
    return { error: "Organization name cannot be empty." };
  }

  const headers = await getAuthHeaders({ contentType: true });

  const idValidation = validatePathIdentifier(
    organizationId,
    "Organization ID is required",
    "Invalid organization ID",
  );
  if ("error" in idValidation) {
    return idValidation;
  }

  const url = new URL(
    `${apiBaseUrl}/organizations/${encodeURIComponent(idValidation.value)}`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "organizations",
          id: idValidation.value,
          attributes: {
            name: trimmed,
          },
        },
      }),
    });

    const result = await handleApiResponse(response);
    if (!hasActionError(result)) {
      revalidatePath("/providers");
    }
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Lists AWS Organizations filtered by external ID.
 * GET /api/v1/organizations?filter[external_id]={externalId}&filter[org_type]=aws
 */
export const listOrganizationsByExternalId = async (externalId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/organizations`);
  url.searchParams.set("filter[external_id]", externalId);
  url.searchParams.set("filter[org_type]", "aws");

  try {
    const response = await fetch(url.toString(), { headers });
    return await handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Lists AWS organizations available for the current tenant.
 * GET /api/v1/organizations?filter[org_type]=aws
 */
export const listOrganizations = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/organizations`);
  url.searchParams.set("filter[org_type]", "aws");

  try {
    const response = await fetch(url.toString(), { headers });
    return await handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const listOrganizationsSafe =
  async (): Promise<OrganizationListResponse> => {
    const url = new URL(`${apiBaseUrl}/organizations`);
    url.searchParams.set("filter[org_type]", "aws");
    url.searchParams.set("page[size]", "100");

    return fetchOptionalCollection<OrganizationListResponse>(url);
  };

/**
 * Lists organization units available for the current tenant.
 * GET /api/v1/organizational-units
 */
export const listOrganizationUnits = async () => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/organizational-units`);

  try {
    const response = await fetch(url.toString(), { headers });
    return await handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

export const listOrganizationUnitsSafe =
  async (): Promise<OrganizationUnitListResponse> => {
    const url = new URL(`${apiBaseUrl}/organizational-units`);
    url.searchParams.set("page[size]", "100");

    return fetchOptionalCollection<OrganizationUnitListResponse>(url);
  };

/**
 * Creates an organization secret (role-based credentials).
 * POST /api/v1/organization-secrets
 */
export const createOrganizationSecret = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/organization-secrets`);

  const organizationId = formData.get("organizationId") as string;
  const roleArn = formData.get("roleArn") as string;
  const externalId = formData.get("externalId") as string;

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "organization-secrets",
          attributes: {
            secret_type: "role",
            secret: {
              role_arn: roleArn,
              external_id: externalId,
            },
          },
          relationships: {
            organization: {
              data: {
                type: "organizations",
                id: organizationId,
              },
            },
          },
        },
      }),
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Updates an organization secret (role-based credentials).
 * PATCH /api/v1/organization-secrets/{id}
 */
export const updateOrganizationSecret = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const organizationSecretId = formData.get("organizationSecretId") as
    | string
    | null;
  const roleArn = formData.get("roleArn") as string;
  const externalId = formData.get("externalId") as string;

  const organizationSecretIdValidation = validatePathIdentifier(
    organizationSecretId,
    "Organization secret ID is required",
    "Invalid organization secret ID",
  );
  if ("error" in organizationSecretIdValidation) {
    return organizationSecretIdValidation;
  }

  const url = new URL(
    `${apiBaseUrl}/organization-secrets/${encodeURIComponent(organizationSecretIdValidation.value)}`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "organization-secrets",
          id: organizationSecretIdValidation.value,
          attributes: {
            secret_type: "role",
            secret: {
              role_arn: roleArn,
              external_id: externalId,
            },
          },
        },
      }),
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Lists organization secrets for an organization.
 * GET /api/v1/organization-secrets?filter[organization_id]={organizationId}
 */
export const listOrganizationSecretsByOrganizationId = async (
  organizationId: string,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/organization-secrets`);
  url.searchParams.set("filter[organization_id]", organizationId);

  try {
    const response = await fetch(url.toString(), { headers });
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Deletes an AWS Organization resource.
 * DELETE /api/v1/organizations/{id}
 */
export const deleteOrganization = async (organizationId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const organizationIdValidation = validatePathIdentifier(
    organizationId,
    "Organization ID is required",
    "Invalid organization ID",
  );
  if ("error" in organizationIdValidation) {
    return organizationIdValidation;
  }

  const url = new URL(
    `${apiBaseUrl}/organizations/${encodeURIComponent(organizationIdValidation.value)}`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Deletes an organizational unit.
 * DELETE /api/v1/organizational-units/{id}
 */
export const deleteOrganizationalUnit = async (
  organizationalUnitId: string,
) => {
  const headers = await getAuthHeaders({ contentType: false });

  const idValidation = validatePathIdentifier(
    organizationalUnitId,
    "Organizational unit ID is required",
    "Invalid organizational unit ID",
  );
  if ("error" in idValidation) {
    return idValidation;
  }

  const url = new URL(
    `${apiBaseUrl}/organizational-units/${encodeURIComponent(idValidation.value)}`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "DELETE",
      headers,
    });

    return handleApiResponse(response, "/providers");
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Triggers an async discovery of the AWS Organization.
 * POST /api/v1/organizations/{id}/discover
 */
export const triggerDiscovery = async (organizationId: string) => {
  const headers = await getAuthHeaders({ contentType: false });
  const organizationIdValidation = validatePathIdentifier(
    organizationId,
    "Organization ID is required",
    "Invalid organization ID",
  );
  if ("error" in organizationIdValidation) {
    return organizationIdValidation;
  }
  const url = new URL(
    `${apiBaseUrl}/organizations/${encodeURIComponent(organizationIdValidation.value)}/discover`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
    });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Polls the discovery status.
 * GET /api/v1/organizations/{orgId}/discoveries/{discoveryId}
 */
export const getDiscovery = async (
  organizationId: string,
  discoveryId: string,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const organizationIdValidation = validatePathIdentifier(
    organizationId,
    "Organization ID is required",
    "Invalid organization ID",
  );
  if ("error" in organizationIdValidation) {
    return organizationIdValidation;
  }
  const discoveryIdValidation = validatePathIdentifier(
    discoveryId,
    "Discovery ID is required",
    "Invalid discovery ID",
  );
  if ("error" in discoveryIdValidation) {
    return discoveryIdValidation;
  }
  const url = new URL(
    `${apiBaseUrl}/organizations/${encodeURIComponent(organizationIdValidation.value)}/discoveries/${encodeURIComponent(discoveryIdValidation.value)}`,
  );

  try {
    const response = await fetch(url.toString(), { headers });

    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Applies discovery results — creates providers, links to org/OUs, auto-generates secrets.
 * POST /api/v1/organizations/{orgId}/discoveries/{discoveryId}/apply
 */
export const applyDiscovery = async (
  organizationId: string,
  discoveryId: string,
  accounts: Array<{ id: string; alias?: string }>,
  organizationalUnits: Array<{ id: string }>,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const organizationIdValidation = validatePathIdentifier(
    organizationId,
    "Organization ID is required",
    "Invalid organization ID",
  );
  if ("error" in organizationIdValidation) {
    return organizationIdValidation;
  }
  const discoveryIdValidation = validatePathIdentifier(
    discoveryId,
    "Discovery ID is required",
    "Invalid discovery ID",
  );
  if ("error" in discoveryIdValidation) {
    return discoveryIdValidation;
  }
  const url = new URL(
    `${apiBaseUrl}/organizations/${encodeURIComponent(organizationIdValidation.value)}/discoveries/${encodeURIComponent(discoveryIdValidation.value)}/apply`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "organization-discoveries",
          attributes: {
            accounts,
            organizational_units: organizationalUnits,
          },
        },
      }),
    });

    const result = await handleApiResponse(response);
    if (!hasActionError(result)) {
      revalidatePath("/providers");
    }
    return result;
  } catch (error) {
    return handleApiError(error);
  }
};
