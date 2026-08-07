"use server";

import { revalidatePath } from "next/cache";

import { apiBaseUrl, getAuthHeaders } from "@/lib";
import { handleApiError, handleApiResponse } from "@/lib/server-actions-helper";
import {
  ApplyDiscoveryPayload,
  CollectionFetch,
  CollectionPage,
  ORGANIZATION_TYPE,
  OrganizationNodeResource,
  OrganizationResource,
  OrganizationType,
  OrgSecretPayload,
  toOrgFlowType,
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

const HIERARCHY_PAGE_SIZE = 100;
/** Runaway guard, not an expected path: 50 × 100 = 5000 resources. */
const HIERARCHY_MAX_PAGES = 50;

/**
 * Fetches a whole collection, following JSON:API pagination — the hierarchy
 * needs every organization and node to group providers, so stopping at the
 * first page would silently drop groups. Same traversal the providers page
 * already does for providers and provider groups (`getAllProviders`).
 *
 * Any incompleteness (a failed page, or the guard) resolves to the degraded
 * result: callers surface "grouping unavailable" and list providers flat, which
 * is truthful, where a partial hierarchy would look complete.
 */
async function fetchOptionalCollection<T>(
  url: URL,
): Promise<CollectionFetch<T>> {
  const collected: T[] = [];

  // Headers inside the try: an expired session throws, and these are awaited in
  // the providers page's `Promise.all`, which has no catch.
  try {
    const headers = await getAuthHeaders({ contentType: false });

    for (let page = 1; page <= HIERARCHY_MAX_PAGES; page += 1) {
      const pageUrl = new URL(url);
      pageUrl.searchParams.set("page[number]", String(page));
      pageUrl.searchParams.set("page[size]", String(HIERARCHY_PAGE_SIZE));

      const response = await fetch(pageUrl.toString(), { headers });

      // Failures go through `handleApiResponse` too — it is the shared
      // reporting point, and short-circuiting on `!response.ok` skipped it.
      const body = (await handleApiResponse(response)) as CollectionPage<T>;

      if (!response.ok) {
        return { data: [], error: true };
      }

      collected.push(...(body.data ?? []));

      // A missing `pages` counts as "this was the only page"; reading it as
      // "maybe more" would walk to the guard on every single-page response.
      if (page >= (body.meta?.pagination?.pages ?? 1)) {
        return { data: collected };
      }
    }

    // Guard exhaustion is not an ordinary fetch failure, and must not look
    // like one in Sentry: report the concrete cause so estates above the cap
    // are triageable instead of silently degraded.
    handleApiError(
      new Error(
        `Organization hierarchy pagination guard exhausted after ${HIERARCHY_MAX_PAGES} pages (${HIERARCHY_MAX_PAGES * HIERARCHY_PAGE_SIZE} resources) for ${url.pathname}`,
      ),
    );

    return { data: [], error: true };
  } catch (error) {
    handleApiError(error);

    return { data: [], error: true };
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

  // Absent means AWS (the flow predates the field); unrecognized is rejected,
  // not coerced to AWS.
  const rawOrgType = formData.get("orgType");
  const orgType =
    rawOrgType === null ? ORGANIZATION_TYPE.AWS : toOrgFlowType(rawOrgType);

  if (!orgType) {
    return { error: "Invalid organization type" };
  }

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
 * Lists every organization for the current tenant, across organization types.
 * GET /api/v1/organizations
 */
export const listOrganizationsSafe = async (): Promise<
  CollectionFetch<OrganizationResource>
> =>
  fetchOptionalCollection<OrganizationResource>(
    new URL(`${apiBaseUrl}/organizations`),
  );

/**
 * Lists every organization node. A large AWS organization can hold hundreds of
 * OUs, so this is the collection most likely to span pages.
 * GET /api/v1/organization-nodes
 */
export const listOrganizationNodesSafe = async (): Promise<
  CollectionFetch<OrganizationNodeResource>
> =>
  fetchOptionalCollection<OrganizationNodeResource>(
    new URL(`${apiBaseUrl}/organization-nodes`),
  );

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
 * Deletes an organization node.
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
 * JSON:API attributes for an apply request.
 */
function buildApplyAttributes(payload: ApplyDiscoveryPayload) {
  switch (payload.orgType) {
    case ORGANIZATION_TYPE.AWS:
      return {
        accounts: payload.accounts,
        organizational_units: payload.organizationalUnits,
      };
    case ORGANIZATION_TYPE.AZURE:
      return { subscriptions: payload.subscriptions };
    case ORGANIZATION_TYPE.GCP:
      return { projects: payload.projects };
  }
}

/**
 * Applies discovery results — creates providers, links to org/nodes,
 * auto-generates secrets. The payload is discriminated by organization type:
 * AWS sends `accounts` + client-side-derived `organizational_units`; GCP sends
 * `projects` and Azure `subscriptions` only (folder / Management Group ancestors
 * are derived server-side).
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
  // No `include`: the apply view rejects the parameter outright and fails the
  // whole request. The created providers' uids are read afterwards instead, with
  // `getProviderUidsByIds`.

  const attributes = buildApplyAttributes(payload);

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
