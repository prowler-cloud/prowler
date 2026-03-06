"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

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
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
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
