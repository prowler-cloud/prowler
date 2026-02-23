"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";

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
  const organizationSecretId = formData.get("organizationSecretId") as string;
  const roleArn = formData.get("roleArn") as string;
  const externalId = formData.get("externalId") as string;

  if (!organizationSecretId) {
    return { error: "Organization secret ID is required" };
  }

  const url = new URL(
    `${apiBaseUrl}/organization-secrets/${organizationSecretId}`,
  );

  try {
    const response = await fetch(url.toString(), {
      method: "PATCH",
      headers,
      body: JSON.stringify({
        data: {
          type: "organization-secrets",
          id: organizationSecretId,
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
  const url = new URL(`${apiBaseUrl}/organizations/${organizationId}/discover`);

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
  const url = new URL(
    `${apiBaseUrl}/organizations/${organizationId}/discoveries/${discoveryId}`,
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
  const url = new URL(
    `${apiBaseUrl}/organizations/${organizationId}/discoveries/${discoveryId}/apply`,
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

    revalidatePath("/providers");
    return handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};
