import {
  listOrganizationsSafe,
  listOrganizationUnitsSafe,
} from "@/actions/organizations/organizations";
import { getProviders } from "@/actions/providers";
import { getScans } from "@/actions/scans";
import {
  extractFiltersAndQuery,
  extractSortAndKey,
} from "@/lib/helper-filters";
import {
  FilterEntity,
  FilterOption,
  OrganizationListResponse,
  OrganizationUnitListResponse,
  OrganizationUnitResource,
  ProvidersApiResponse,
  SearchParamsProps,
} from "@/types";
import {
  PROVIDERS_GROUP_KIND,
  PROVIDERS_PAGE_FILTER,
  PROVIDERS_ROW_TYPE,
  ProvidersAccountsViewData,
  ProvidersOrganizationRow,
  ProvidersProviderRow,
  ProvidersTableRow,
  ProvidersTableRowsInput,
} from "@/types/providers-table";
import { SCAN_TRIGGER, ScanProps } from "@/types/scans";

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

const ACTIVE_SCAN_STATES = new Set(["scheduled", "available", "executing"]);

const buildScheduledProviderIds = (scans: ScanProps[]): Set<string> => {
  const scheduled = new Set<string>();

  for (const scan of scans) {
    if (
      scan.attributes.trigger === SCAN_TRIGGER.SCHEDULED &&
      ACTIVE_SCAN_STATES.has(scan.attributes.state)
    ) {
      const providerId = scan.relationships.provider?.data?.id;
      if (providerId) {
        scheduled.add(providerId);
      }
    }
  }

  return scheduled;
};

const enrichProviders = (
  providersResponse?: ProvidersApiResponse,
  scheduledProviderIds?: Set<string>,
): ProvidersProviderRow[] => {
  const providerGroupLookup = createProviderGroupLookup(providersResponse);

  return (providersResponse?.data ?? []).map((provider) => ({
    ...provider,
    rowType: PROVIDERS_ROW_TYPE.PROVIDER,
    groupNames:
      provider.relationships.provider_groups.data.map(
        (providerGroup: { id: string }) =>
          providerGroupLookup.get(providerGroup.id) ?? "Unknown Group",
      ) ?? [],
    hasSchedule: scheduledProviderIds?.has(provider.id) ?? false,
  }));
};

const createOrganizationRow = ({
  groupKind,
  id,
  name,
  externalId,
  organizationId,
  parentExternalId,
  subRows,
}: {
  externalId: string | null;
  groupKind: ProvidersOrganizationRow["groupKind"];
  id: string;
  name: string;
  organizationId: string | null;
  parentExternalId: string | null;
  subRows: ProvidersTableRow[];
}): ProvidersOrganizationRow => ({
  id,
  rowType: PROVIDERS_ROW_TYPE.ORGANIZATION,
  groupKind,
  name,
  externalId,
  organizationId,
  parentExternalId,
  providerCount: countProviderRows(subRows),
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

function getOrganizationUnitParentId(
  organizationUnit: OrganizationUnitResource,
): string | null {
  return organizationUnit.relationships.parent?.data?.id ?? null;
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

function countProviderRows(rows: ProvidersTableRow[]): number {
  return rows.reduce((total, row) => {
    if (row.rowType === PROVIDERS_ROW_TYPE.PROVIDER) {
      return total + 1;
    }

    return total + countProviderRows(row.subRows);
  }, 0);
}

function getOrganizationUnitRelationshipId(
  provider: ProvidersProviderRow,
): string | null {
  return (
    provider.relationships.organization_unit?.data?.id ??
    provider.relationships.organizational_unit?.data?.id ??
    null
  );
}

function buildOrganizationUnitRows({
  organizationId,
  organizationUnits,
  providerLookup,
  providersByOrganizationUnitId,
  useParentIdRelationships,
  parentExternalId,
  parentOrganizationUnitId,
  maxDepth = 10,
}: {
  organizationId: string;
  organizationUnits: OrganizationUnitResource[];
  parentExternalId: string | null;
  parentOrganizationUnitId: string | null;
  providerLookup: Map<string, ProvidersProviderRow>;
  providersByOrganizationUnitId: Map<string, ProvidersProviderRow[]>;
  useParentIdRelationships: boolean;
  maxDepth?: number;
}): ProvidersOrganizationRow[] {
  if (maxDepth <= 0) {
    return [];
  }

  return organizationUnits
    .filter(
      (organizationUnit) =>
        organizationUnit.relationships.organization.data.id ===
          organizationId &&
        (useParentIdRelationships
          ? getOrganizationUnitParentId(organizationUnit) ===
            parentOrganizationUnitId
          : organizationUnit.attributes.parent_external_id ===
            parentExternalId),
    )
    .map((organizationUnit) => {
      const childOrganizationUnitRows = buildOrganizationUnitRows({
        organizationId,
        organizationUnits,
        parentOrganizationUnitId: organizationUnit.id,
        parentExternalId: organizationUnit.attributes.external_id,
        providerLookup,
        providersByOrganizationUnitId,
        useParentIdRelationships,
        maxDepth: maxDepth - 1,
      });
      const providerRowsFromRelationships = getProviderRowsByIds({
        providerIds: getRelationshipProviderIds(organizationUnit.relationships),
        providerLookup,
      });
      const providerRows =
        providerRowsFromRelationships.length > 0
          ? providerRowsFromRelationships
          : (providersByOrganizationUnitId.get(organizationUnit.id) ?? []);
      const subRows = [...childOrganizationUnitRows, ...providerRows];

      return createOrganizationRow({
        groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION_UNIT,
        id: organizationUnit.id,
        name: organizationUnit.attributes.name,
        externalId: organizationUnit.attributes.external_id,
        organizationId,
        parentExternalId: organizationUnit.attributes.parent_external_id,
        subRows,
      });
    })
    .filter((organizationUnitRow) => organizationUnitRow.subRows.length > 0);
}

export function buildProvidersTableRows({
  isCloud,
  organizations,
  organizationUnits,
  providers,
}: ProvidersTableRowsInput): ProvidersTableRow[] {
  if (!isCloud) {
    return providers;
  }

  const providerLookup = new Map(
    providers.map((provider) => [provider.id, provider] as const),
  );
  const providersByOrganizationId = new Map<string, ProvidersProviderRow[]>();
  const providersByOrganizationUnitId = new Map<
    string,
    ProvidersProviderRow[]
  >();

  for (const provider of providers) {
    const organizationId =
      provider.relationships.organization?.data?.id ?? null;
    const organizationUnitId = getOrganizationUnitRelationshipId(provider);

    if (organizationUnitId) {
      const organizationUnitProviders =
        providersByOrganizationUnitId.get(organizationUnitId) ?? [];
      organizationUnitProviders.push(provider);
      providersByOrganizationUnitId.set(
        organizationUnitId,
        organizationUnitProviders,
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

  const useParentIdRelationships = organizationUnits.some(
    (organizationUnit) => organizationUnit.relationships.parent !== undefined,
  );

  // Build a set of provider IDs that are assigned to OUs, so we can
  // exclude them from the org's direct children and avoid duplication.
  const providersAssignedToOu = new Set(
    Array.from(providersByOrganizationUnitId.values()).flatMap((providers) =>
      providers.map((p) => p.id),
    ),
  );

  const organizationRows = organizations
    .map((organization) => {
      const organizationUnitRows = buildOrganizationUnitRows({
        organizationId: organization.id,
        organizationUnits,
        parentOrganizationUnitId: null,
        parentExternalId: organization.attributes.root_external_id,
        providerLookup,
        providersByOrganizationUnitId,
        useParentIdRelationships,
      });

      // Collect all provider IDs already placed inside OUs to avoid duplication
      // at the org level. This covers both relationship-based and fallback assignments.
      const providersInOus = new Set<string>();
      function collectOuProviderIds(rows: ProvidersTableRow[]) {
        for (const row of rows) {
          if (row.rowType === PROVIDERS_ROW_TYPE.PROVIDER) {
            providersInOus.add(row.id);
          } else {
            collectOuProviderIds(row.subRows);
          }
        }
      }
      collectOuProviderIds(organizationUnitRows);

      const organizationProvidersFromRelationships = getProviderRowsByIds({
        providerIds: getRelationshipProviderIds(organization.relationships),
        providerLookup,
      }).filter(
        (provider) =>
          !providersAssignedToOu.has(provider.id) &&
          !providersInOus.has(provider.id),
      );
      const organizationProviders =
        organizationProvidersFromRelationships.length > 0
          ? organizationProvidersFromRelationships
          : (providersByOrganizationId.get(organization.id) ?? []).filter(
              (provider) => !providersInOus.has(provider.id),
            );
      const subRows = [...organizationProviders, ...organizationUnitRows];

      return createOrganizationRow({
        groupKind: PROVIDERS_GROUP_KIND.ORGANIZATION,
        id: organization.id,
        name: organization.attributes.name,
        externalId: organization.attributes.external_id,
        organizationId: organization.id,
        parentExternalId: organization.attributes.root_external_id,
        subRows,
      });
    })
    .filter((organizationRow) => organizationRow.subRows.length > 0);

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
    providerFilters[`filter[${PROVIDERS_PAGE_FILTER.PROVIDER_TYPE}]`];
  if (providerTypeFilter) {
    providerFilters[`filter[${PROVIDERS_PAGE_FILTER.PROVIDER}]`] =
      providerTypeFilter;
  }

  delete providerFilters[`filter[${PROVIDERS_PAGE_FILTER.PROVIDER_TYPE}]`];

  const emptyOrganizationsResponse: OrganizationListResponse = {
    data: [],
  };
  const emptyOrganizationUnitsResponse: OrganizationUnitListResponse = {
    data: [],
  };

  const [
    providersResponse,
    allProvidersResponse,
    scansResponse,
    organizationsResponse,
    organizationUnitsResponse,
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
    resolveActionResult(getProviders({ pageSize: 500 })),
    // Fetch active scheduled scans to determine daily schedule per provider
    resolveActionResult(
      getScans({
        pageSize: 500,
        filters: {
          "filter[trigger]": SCAN_TRIGGER.SCHEDULED,
          "filter[state__in]": "scheduled,available",
        },
      }),
    ),
    isCloud
      ? listOrganizationsSafe()
      : Promise.resolve(emptyOrganizationsResponse),
    isCloud
      ? listOrganizationUnitsSafe()
      : Promise.resolve(emptyOrganizationUnitsResponse),
  ]);

  const scheduledProviderIds = buildScheduledProviderIds(
    scansResponse?.data ?? [],
  );

  const orgs = organizationsResponse?.data ?? [];
  const ous = organizationUnitsResponse?.data ?? [];
  const providers = enrichProviders(providersResponse, scheduledProviderIds);

  const rows = buildProvidersTableRows({
    isCloud,
    organizations: orgs,
    organizationUnits: ous,
    providers,
  });

  return {
    filters: createProvidersFilters(),
    metadata: providersResponse?.meta,
    providers: allProvidersResponse?.data ?? [],
    rows,
  };
}

export { PROVIDERS_ROW_TYPE };
