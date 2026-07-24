"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  ApplyDiscoveryPayload,
  ORGANIZATION_TYPE,
  OrganizationListResponse,
  OrganizationNodeListResponse,
  OrganizationType,
  OrgSecretPayload,
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

// Never throws: on failure it yields an empty collection flagged with
// `error: true` so callers can distinguish a degraded fetch from a genuinely
// empty hierarchy (see providers-page degraded-view signaling).
async function fetchOptionalCollection<T extends { data: unknown[] }>(
  url: URL,
): Promise<T & { error?: boolean }> {
  const headers = await getAuthHeaders({ contentType: false });

  try {
    const response = await fetch(url.toString(), { headers });

    if (!response.ok) {
      return { data: [], error: true } as unknown as T & { error?: boolean };
    }

    return (await handleApiResponse(response)) as T;
  } catch {
    return { data: [], error: true } as unknown as T & { error?: boolean };
  }
}

/**
 * Creates an Organization resource for the given organization type.
 * POST /api/v1/organizations
 */
export const createOrganization = async (formData: FormData) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/organizations`);

  const name = formData.get("name") as string;
  const externalId = formData.get("externalId") as string;
  const orgType =
    (formData.get("orgType") as OrganizationType | null) ??
    ORGANIZATION_TYPE.AWS;

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "organizations",
          attributes: {
            name,
            org_type: orgType,
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
 * Updates an Organization's name.
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
 * Lists organizations filtered by external ID and organization type.
 * GET /api/v1/organizations?filter[external_id]={externalId}&filter[org_type]={orgType}
 */
export const listOrganizationsByExternalId = async (
  externalId: string,
  orgType: OrganizationType = ORGANIZATION_TYPE.AWS,
) => {
  const headers = await getAuthHeaders({ contentType: false });
  const url = new URL(`${apiBaseUrl}/organizations`);
  url.searchParams.set("filter[external_id]", externalId);
  url.searchParams.set("filter[org_type]", orgType);

  try {
    const response = await fetch(url.toString(), { headers });
    return await handleApiResponse(response);
  } catch (error) {
    return handleApiError(error);
  }
};

/**
 * Lists all organizations for the current tenant, across organization types.
 * GET /api/v1/organizations
 */
export const listOrganizationsSafe = async (): Promise<
  OrganizationListResponse & { error?: boolean }
> => {
  const url = new URL(`${apiBaseUrl}/organizations`);
  url.searchParams.set("page[size]", "100");

  return fetchOptionalCollection<OrganizationListResponse>(url);
};

/**
 * Lists organization nodes (AWS organizational units, GCP folders) via the
 * canonical route.
 * GET /api/v1/organization-nodes
 */
export const listOrganizationNodesSafe = async (): Promise<
  OrganizationNodeListResponse & { error?: boolean }
> => {
  const url = new URL(`${apiBaseUrl}/organization-nodes`);
  url.searchParams.set("page[size]", "100");

  return fetchOptionalCollection<OrganizationNodeListResponse>(url);
};

/**
 * Creates an organization secret for the given secret payload.
 * POST /api/v1/organization-secrets
 */
export const createOrganizationSecret = async (
  organizationId: string,
  payload: OrgSecretPayload,
) => {
  const headers = await getAuthHeaders({ contentType: true });
  const url = new URL(`${apiBaseUrl}/organization-secrets`);

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "organization-secrets",
          attributes: {
            secret_type: payload.secretType,
            secret: payload.secret,
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
 * Updates an organization secret with the given secret payload.
 * PATCH /api/v1/organization-secrets/{id}
 */
export const updateOrganizationSecret = async (
  organizationSecretId: string,
  payload: OrgSecretPayload,
) => {
  const headers = await getAuthHeaders({ contentType: true });

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
            secret_type: payload.secretType,
            secret: payload.secret,
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
 * Deletes an Organization resource.
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
 * Deletes an organization node (AWS organizational unit, GCP folder) via the
 * canonical route.
 * DELETE /api/v1/organization-nodes/{id}
 */
export const deleteOrganizationNode = async (organizationNodeId: string) => {
  const headers = await getAuthHeaders({ contentType: false });

  const idValidation = validatePathIdentifier(
    organizationNodeId,
    "Organization node ID is required",
    "Invalid organization node ID",
  );
  if ("error" in idValidation) {
    return idValidation;
  }

  const url = new URL(
    `${apiBaseUrl}/organization-nodes/${encodeURIComponent(idValidation.value)}`,
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
 * Triggers an async discovery of the Organization.
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
 * Applies discovery results — creates providers, links to org/nodes,
 * auto-generates secrets. The payload is discriminated by organization type:
 * AWS sends `accounts` + client-side-derived `organizational_units`; GCP sends
 * `projects` only (folder ancestors are derived server-side).
 * POST /api/v1/organizations/{orgId}/discoveries/{discoveryId}/apply
 */
export const applyDiscovery = async (
  organizationId: string,
  discoveryId: string,
  payload: ApplyDiscoveryPayload,
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

  const attributes =
    payload.orgType === ORGANIZATION_TYPE.AWS
      ? {
          accounts: payload.accounts,
          organizational_units: payload.organizationalUnits,
        }
      : { projects: payload.projects };

  try {
    const response = await fetch(url.toString(), {
      method: "POST",
      headers,
      body: JSON.stringify({
        data: {
          type: "organization-discoveries",
          attributes,
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
