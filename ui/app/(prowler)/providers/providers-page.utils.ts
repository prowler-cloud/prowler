import { getAllProviderGroups } from "@/actions/manage-groups/manage-groups";
import {
  listOrganizationNodesSafe,
  listOrganizationsSafe,
} from "@/actions/organizations/organizations";
import { getAllProviders, getProviders } from "@/actions/providers";
import { PROVIDERS_FILTER_PARAM } from "@/actions/providers/providers-filters";
import { getSchedules } from "@/actions/schedules";
import {
  extractFiltersAndQuery,
  extractSortAndKey,
} from "@/lib/helper-filters";
import {
  buildProviderScheduleSummary,
  buildScheduleAttributesFromProvider,
  buildSchedulesByProviderId,
  isScheduleConfigured,
} from "@/lib/schedules";
import {
  CollectionFetch,
  FilterEntity,
  FilterOption,
  OrganizationNodeResource,
  OrganizationResource,
  OrganizationType,
  ProvidersApiResponse,
  SearchParamsProps,
} from "@/types";
import {
  HIERARCHY_STATUS,
  HierarchyStatus,
  PROVIDERS_GROUP_KIND,
  PROVIDERS_PAGE_FILTER,
  PROVIDERS_ROW_TYPE,
  ProvidersAccountsViewData,
  ProvidersOrganizationRow,
  ProvidersProviderRow,
  ProvidersTableRow,
  ProvidersTableRowsInput,
} from "@/types/providers-table";
import { ScanScheduleSummary } from "@/types/scans";
import { ScheduleAttributes } from "@/types/schedules";

const PROVIDERS_STATUS_MAPPING = [
  {
    true: {
      label: "Connected",
      value: "true",
    },
  },
  {
    false: {
      label: "Not connected",
      value: "false",
    },
  },
] as Array<{ [key: string]: FilterEntity }>;

interface ProvidersAccountsViewInput {
  isCloud: boolean;
  searchParams: SearchParamsProps;
}

function hasActionError(result: unknown): result is {
  error: unknown;
} {
  return Boolean(
    result &&
      typeof result === "object" &&
      "error" in (result as Record<string, unknown>) &&
      (result as Record<string, unknown>).error !== null &&
      (result as Record<string, unknown>).error !== undefined,
  );
}

async function resolveActionResult<T>(
  action: Promise<T | undefined>,
  fallback?: T,
): Promise<T | undefined> {
  try {
    const result = await action;

    if (hasActionError(result)) {
      return fallback;
    }

    return result ?? fallback;
  } catch {
    return fallback;
  }
}

const createProvidersFilters = (): FilterOption[] => {
  return [
    {
      key: PROVIDERS_PAGE_FILTER.STATUS,
      labelCheckboxGroup: "Status",
      values: ["true", "false"],
      valueLabelMapping: PROVIDERS_STATUS_MAPPING,
      index: 0,
    },
  ];
};

const createProviderGroupLookup = (
  providersResponse?: ProvidersApiResponse,
): Map<string, string> => {
  const lookup = new Map<string, string>();

  for (const includedItem of providersResponse?.included ?? []) {
    if (
      includedItem.type === "provider-groups" &&
      typeof includedItem.attributes?.name === "string"
    ) {
      lookup.set(includedItem.id, includedItem.attributes.name);
    }
  }

  return lookup;
};

// A schedule is backed by the Provider row itself, so its `/schedules` entry
// exists before the first scheduled Scan is materialized — only enabled,
// configured ones carry a displayable cadence summary.
const buildProviderScheduleSummaryFor = (
  attributes: ScheduleAttributes | undefined,
  now: Date,
): ScanScheduleSummary | undefined =>
  attributes && attributes.scan_enabled && isScheduleConfigured(attributes)
    ? buildProviderScheduleSummary(attributes, now)
    : undefined;

const getProviderLastScanAt = (
  provider: ProvidersApiResponse["data"][number],
): string | null => {
  if (
    Object.prototype.hasOwnProperty.call(provider.attributes, "last_scan_at")
  ) {
    return provider.attributes.last_scan_at ?? null;
  }

  return provider.attributes.connection.last_checked_at ?? null;
};

const enrichProviders = (
  providersResponse: ProvidersApiResponse | undefined,
  schedulesByProviderId: Record<string, ScheduleAttributes>,
): ProvidersProviderRow[] => {
  const providerGroupLookup = createProviderGroupLookup(providersResponse);
  const now = new Date();

  return (providersResponse?.data ?? []).map((provider) => {
    const providerScheduleAttributes = buildScheduleAttributesFromProvider(
      provider.attributes,
    );
    const scheduleAttributes =
      providerScheduleAttributes ?? schedulesByProviderId[provider.id];
    const scheduleSummary = buildProviderScheduleSummaryFor(
      scheduleAttributes,
      now,
    );

    return {
      ...provider,
      rowType: PROVIDERS_ROW_TYPE.PROVIDER,
      groupNames:
        provider.relationships.provider_groups.data.map(
          (providerGroup: { id: string }) =>
            providerGroupLookup.get(providerGroup.id) ?? "Unknown Group",
        ) ?? [],
      // Provider scan_* fields are authoritative when present; otherwise we
      // only fall back to the /schedules resource, never materialized scans.
      hasSchedule: scheduleSummary !== undefined,
      scheduleSummary,
      lastScanAt: getProviderLastScanAt(provider),
    };
  });
};

const createOrganizationRow = ({
  groupKind,
  orgType,
  kind,
  id,
  name,
  externalId,
  organizationId,
  parentExternalId,
  providerIds,
  subRows,
}: {
  externalId: string | null;
  groupKind: ProvidersOrganizationRow["groupKind"];
  orgType: OrganizationType;
  kind?: ProvidersOrganizationRow["kind"];
  id: string;
  name: string;
  organizationId: string | null;
  parentExternalId: string | null;
  providerIds: string[];
  subRows: ProvidersTableRow[];
}): ProvidersOrganizationRow => ({
  id,
  rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
  groupKind,
  orgType,
  kind,
  name,
  externalId,
  organizationId,
  parentExternalId,
  providerCount: providerIds.length,
  providerIds,
  subRows,
});

function getRelationshipProviderIds(
  relationships:
    | {
        providers?: {
          data?: Array<{ id: string; type: string }>;
        };
      }
    | undefined,
): string[] {
  return relationships?.providers?.data?.map((provider) => provider.id) ?? [];
}

function getOrganizationNodeParentId(
  organizationNode: OrganizationNodeResource,
): string | null {
  return organizationNode.relationships.parent?.data?.id ?? null;
}

function getProviderRowsByIds({
  providerIds,
  providerLookup,
}: {
  providerIds: string[];
  providerLookup: Map<string, ProvidersProviderRow>;
}): ProvidersProviderRow[] {
  return providerIds
    .map((providerId) => providerLookup.get(providerId))
    .filter((provider): provider is ProvidersProviderRow => Boolean(provider));
}

/**
 * Resolves a group's direct providers: the `providers` relationship when the API
 * serves one, the reverse-lookup map otherwise.
 */
function resolveProviderRowsAndIds({
  relationships,
  fallbackProviders,
  providerLookup,
  excludeIds,
}: {
  relationships: Parameters<typeof getRelationshipProviderIds>[0];
  fallbackProviders: ProvidersProviderRow[];
  providerLookup: Map<string, ProvidersProviderRow>;
  excludeIds?: ReadonlySet<string>;
}): { providerRows: ProvidersProviderRow[]; directProviderIds: string[] } {
  const isIncluded = (provider: ProvidersProviderRow) =>
    !excludeIds?.has(provider.id);
  const relationshipProviderIds = getRelationshipProviderIds(relationships);
  const rowsFromRelationships = getProviderRowsByIds({
    providerIds: relationshipProviderIds,
    providerLookup,
  }).filter(isIncluded);

  if (rowsFromRelationships.length > 0) {
    return {
      providerRows: rowsFromRelationships,
      // The relationship ids, not the resolved rows: the lookup holds only the
      // current page, while the id set drives the group's counts and filtering.
      directProviderIds: relationshipProviderIds,
    };
  }

  const providerRows = fallbackProviders.filter(isIncluded);

  return {
    providerRows,
    directProviderIds: providerRows.map((provider) => provider.id),
  };
}

function dedupeIds(ids: string[]): string[] {
  return Array.from(new Set(ids));
}

function collectOrganizationRowProviderIds(
  rows: ProvidersOrganizationRow[],
): string[] {
  return dedupeIds(rows.flatMap((row) => row.providerIds));
}

function getOrganizationNodeRelationshipId(
  provider: ProvidersProviderRow,
): string | null {
  return (
    provider.relationships.organization_node?.data?.id ??
    provider.relationships.organization_unit?.data?.id ??
    provider.relationships.organizational_unit?.data?.id ??
    null
  );
}

function buildOrganizationNodeRows({
  organizationId,
  organizationType,
  organizationNodes,
  providerLookup,
  providersByOrganizationNodeId,
  useParentIdRelationships,
  parentExternalId,
  parentOrganizationNodeId,
  maxDepth = 10,
}: {
  organizationId: string;
  organizationType: OrganizationType;
  organizationNodes: OrganizationNodeResource[];
  parentExternalId: string | null;
  parentOrganizationNodeId: string | null;
  providerLookup: Map<string, ProvidersProviderRow>;
  providersByOrganizationNodeId: Map<string, ProvidersProviderRow[]>;
  useParentIdRelationships: boolean;
  maxDepth?: number;
}): ProvidersOrganizationRow[] {
  if (maxDepth <= 0) {
    return [];
  }

  return organizationNodes
    .filter(
      (organizationNode) =>
        organizationNode.relationships.organization.data.id ===
          organizationId &&
        (useParentIdRelationships
          ? getOrganizationNodeParentId(organizationNode) ===
            parentOrganizationNodeId
          : organizationNode.attributes.parent_external_id ===
            parentExternalId),
    )
    .map((organizationNode) => {
      const childOrganizationNodeRows = buildOrganizationNodeRows({
        organizationId,
        organizationType,
        organizationNodes,
        parentOrganizationNodeId: organizationNode.id,
        parentExternalId: organizationNode.attributes.external_id,
        providerLookup,
        providersByOrganizationNodeId,
        useParentIdRelationships,
        maxDepth: maxDepth - 1,
      });
      const { providerRows, directProviderIds } = resolveProviderRowsAndIds({
        relationships: organizationNode.relationships,
        fallbackProviders:
          providersByOrganizationNodeId.get(organizationNode.id) ?? [],
        providerLookup,
      });
      const subRows = [...childOrganizationNodeRows, ...providerRows];
      const childProviderIds = collectOrganizationRowProviderIds(
        childOrganizationNodeRows,
      );

      return createOrganizationRow({
        groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION_UNIT,
        orgType: organizationType,
        kind: organizationNode.attributes.kind,
        id: organizationNode.id,
        name: organizationNode.attributes.name,
        externalId: organizationNode.attributes.external_id,
        organizationId,
        parentExternalId:
          organizationNode.attributes.parent_external_id ?? null,
        providerIds: dedupeIds([...childProviderIds, ...directProviderIds]),
        subRows,
      });
    })
    .filter(
      (organizationNodeRow) => organizationNodeRow.providerIds.length > 0,
    );
}

export function buildProvidersTableRows({
  isCloud,
  organizations,
  organizationNodes,
  providers,
}: ProvidersTableRowsInput): ProvidersTableRow[] {
  if (!isCloud) {
    return providers;
  }

  const providerLookup = new Map(
    providers.map((provider) => [provider.id, provider] as const),
  );
  const providersByOrganizationId = new Map<string, ProvidersProviderRow[]>();
  const providersByOrganizationNodeId = new Map<
    string,
    ProvidersProviderRow[]
  >();

  for (const provider of providers) {
    const organizationId =
      provider.relationships.organization?.data?.id ?? null;
    const organizationNodeId = getOrganizationNodeRelationshipId(provider);

    if (organizationNodeId) {
      const organizationNodeProviders =
        providersByOrganizationNodeId.get(organizationNodeId) ?? [];
      organizationNodeProviders.push(provider);
      providersByOrganizationNodeId.set(
        organizationNodeId,
        organizationNodeProviders,
      );
      continue;
    }

    if (organizationId) {
      const organizationProviders =
        providersByOrganizationId.get(organizationId) ?? [];
      organizationProviders.push(provider);
      providersByOrganizationId.set(organizationId, organizationProviders);
    }
  }

  // Build a set of provider IDs that are assigned to nodes, so we can
  // exclude them from the org's direct children and avoid duplication.
  const providersAssignedToNode = new Set(
    Array.from(providersByOrganizationNodeId.values()).flatMap((providers) =>
      providers.map((p) => p.id),
    ),
  );

  const organizationRows = organizations
    .map((organization) => {
      const organizationType = organization.attributes.org_type;
      // Which parent link to follow is decided per organization, not across the
      // whole collection: one organization serving `parent` would otherwise make
      // every organization read its nodes that way, and those lacking the
      // relationship would resolve every parent to null — collapsing their nodes
      // to the root, emptying the intermediate rows and dropping them entirely.
      const useParentIdRelationships = organizationNodes.some(
        (organizationNode) =>
          organizationNode.relationships.organization.data.id ===
            organization.id &&
          organizationNode.relationships.parent !== undefined,
      );
      const organizationNodeRows = buildOrganizationNodeRows({
        organizationId: organization.id,
        organizationType,
        organizationNodes,
        parentOrganizationNodeId: null,
        parentExternalId: organization.attributes.root_external_id,
        providerLookup,
        providersByOrganizationNodeId,
        useParentIdRelationships,
      });

      // Collect all provider IDs already placed inside nodes to avoid
      // duplication at the org level. Covers relationship + fallback assignments.
      const providersInNodes = new Set<string>();
      function collectNodeProviderIds(rows: ProvidersTableRow[]) {
        for (const row of rows) {
          if (row.rowType === PROVIDERS_ROW_TYPE.PROVIDER) {
            providersInNodes.add(row.id);
          } else {
            collectNodeProviderIds(row.subRows);
          }
        }
      }
      collectNodeProviderIds(organizationNodeRows);

      // One exclude set for both branches: the fallback map skips providers that
      // carry a node relationship, so `providersAssignedToNode` can only ever
      // match on the relationship branch.
      const { providerRows: organizationProviders, directProviderIds } =
        resolveProviderRowsAndIds({
          relationships: organization.relationships,
          fallbackProviders:
            providersByOrganizationId.get(organization.id) ?? [],
          providerLookup,
          excludeIds: new Set([
            ...Array.from(providersAssignedToNode),
            ...Array.from(providersInNodes),
          ]),
        });
      const subRows = [...organizationProviders, ...organizationNodeRows];
      const organizationNodeProviderIds =
        collectOrganizationRowProviderIds(organizationNodeRows);

      return createOrganizationRow({
        groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION,
        orgType: organizationType,
        id: organization.id,
        name: organization.attributes.name,
        externalId: organization.attributes.external_id,
        organizationId: organization.id,
        parentExternalId: organization.attributes.root_external_id,
        providerIds: dedupeIds([
          ...directProviderIds,
          ...organizationNodeProviderIds,
        ]),
        subRows,
      });
    })
    .filter((organizationRow) => organizationRow.providerIds.length > 0);

  const assignedProviderIds = new Set<string>();

  function collectAssignedProviderIds(rows: ProvidersTableRow[]) {
    for (const row of rows) {
      if (row.rowType === PROVIDERS_ROW_TYPE.PROVIDER) {
        assignedProviderIds.add(row.id);
        continue;
      }

      collectAssignedProviderIds(row.subRows);
    }
  }

  collectAssignedProviderIds(organizationRows);
  const orphanProviders = providers.filter(
    (provider) => !assignedProviderIds.has(provider.id),
  );

  return [...organizationRows, ...orphanProviders];
}

export async function loadProvidersAccountsViewData({
  isCloud,
  searchParams,
}: ProvidersAccountsViewInput): Promise<ProvidersAccountsViewData> {
  const page = parseInt(searchParams.page?.toString() ?? "1", 10);
  const pageSize = parseInt(searchParams.pageSize?.toString() ?? "10", 10);
  const { encodedSort } = extractSortAndKey(searchParams);
  const { filters, query } = extractFiltersAndQuery(searchParams);

  const providerFilters = { ...filters };

  // Map provider_type__in (used by ProviderTypeSelector) to provider__in (API param)
  const providerTypeFilter =
    providerFilters[PROVIDERS_FILTER_PARAM.PROVIDER_TYPE];
  if (providerTypeFilter) {
    providerFilters[PROVIDERS_FILTER_PARAM.PROVIDER] = providerTypeFilter;
  }

  delete providerFilters[PROVIDERS_FILTER_PARAM.PROVIDER_TYPE];

  const emptyOrganizationsResponse: CollectionFetch<OrganizationResource> = {
    data: [],
  };
  const emptyOrganizationNodesResponse: CollectionFetch<OrganizationNodeResource> =
    {
      data: [],
    };

  const [
    providersResponse,
    allProvidersResponse,
    allProviderGroupsResponse,
    schedulesResponse,
    organizationsResponse,
    organizationNodesResponse,
  ] = await Promise.all([
    resolveActionResult(
      getProviders({
        filters: providerFilters,
        page,
        pageSize,
        query,
        sort: encodedSort,
      }),
    ),
    // Unfiltered fetch for ProviderTypeSelector — only needs distinct types;
    // TODO: Replace with a dedicated lightweight endpoint when available.
    resolveActionResult(getAllProviders()),
    // Unfiltered fetch for the Provider Group selector dropdown.
    resolveActionResult(getAllProviderGroups()),
    // Fetch configured schedules as a fallback when provider scan_* fields are
    // absent (best-effort: typically empty in OSS).
    resolveActionResult(getSchedules()),
    isCloud
      ? listOrganizationsSafe()
      : Promise.resolve(emptyOrganizationsResponse),
    isCloud
      ? listOrganizationNodesSafe()
      : Promise.resolve(emptyOrganizationNodesResponse),
  ]);

  const schedulesByProviderId = buildSchedulesByProviderId(schedulesResponse);

  const orgs = organizationsResponse.data;
  const nodes = organizationNodesResponse.data;
  const providers = enrichProviders(providersResponse, schedulesByProviderId);

  const hierarchyStatus: HierarchyStatus =
    isCloud &&
    (Boolean(organizationsResponse.error) ||
      Boolean(organizationNodesResponse.error))
      ? HIERARCHY_STATUS.UNAVAILABLE
      : HIERARCHY_STATUS.AVAILABLE;

  // Whatever was read is still rendered; the notice is worded for both partial
  // shapes rather than promising a flat list.
  const rows = buildProvidersTableRows({
    isCloud,
    organizations: orgs,
    organizationNodes: nodes,
    providers,
  });

  return {
    filters: createProvidersFilters(),
    metadata: providersResponse?.meta,
    providers: allProvidersResponse?.data ?? [],
    providerGroups: allProviderGroupsResponse?.data ?? [],
    rows,
    hierarchyStatus,
  };
}

export { PROVIDERS_ROW_TYPE };
