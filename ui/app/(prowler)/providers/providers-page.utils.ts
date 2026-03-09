import { getProviderGroups } from "@/actions/manage-groups";
import {
  listOrganizationsSafe,
  listOrganizationUnitsSafe,
} from "@/actions/organizations/organizations";
import { getProviders } from "@/actions/providers";
import {
  extractFiltersAndQuery,
  extractSortAndKey,
} from "@/lib/helper-filters";
import {
  FilterEntity,
  FilterOption,
  OrganizationListResponse,
  OrganizationResource,
  OrganizationUnitListResponse,
  OrganizationUnitResource,
  ProviderGroupsResponse,
  ProvidersApiResponse,
  SearchParamsProps,
} from "@/types";
import {
  PROVIDER_DISPLAY_NAMES,
  PROVIDER_TYPES,
  ProviderType,
} from "@/types/providers";
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

const PROVIDER_TYPE_MAPPING = PROVIDER_TYPES.map((providerType) => ({
  [providerType]: {
    provider: providerType as ProviderType,
    uid: "",
    alias: PROVIDER_DISPLAY_NAMES[providerType],
  },
}));

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

interface ProvidersTableLocalFilters {
  organizationIds: string[];
  providerGroupIds: string[];
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

const createProvidersFilters = ({
  isCloud,
  organizations,
  providerGroups,
}: {
  isCloud: boolean;
  organizations: OrganizationResource[];
  providerGroups: ProviderGroupsResponse["data"];
}): FilterOption[] => {
  // Provider type and account selection are handled by ProviderTypeSelector
  // and AccountsSelector. These filters go in the expandable "More Filters" section.
  const filters: FilterOption[] = [];

  if (isCloud && organizations.length > 0) {
    filters.push({
      key: PROVIDERS_PAGE_FILTER.ORGANIZATION,
      labelCheckboxGroup: "Organizations",
      values: organizations.map((organization) => organization.id),
      index: 0,
      valueLabelMapping: organizations.map((organization) => ({
        [organization.id]: {
          provider: "aws",
          uid: organization.attributes.external_id,
          alias: organization.attributes.name,
        },
      })),
    });
  }

  filters.push({
    key: PROVIDERS_PAGE_FILTER.ACCOUNT_GROUP,
    labelCheckboxGroup: "Account Groups",
    values: providerGroups.map((providerGroup) => providerGroup.id),
    index: 1,
    valueLabelMapping: providerGroups.map((providerGroup) => ({
      [providerGroup.id]: {
        provider: "aws",
        uid: providerGroup.id,
        alias: providerGroup.attributes.name,
      },
    })),
  });

  filters.push({
    key: PROVIDERS_PAGE_FILTER.STATUS,
    labelCheckboxGroup: "Status",
    values: ["true", "false"],
    valueLabelMapping: PROVIDERS_STATUS_MAPPING,
    index: 2,
  });

  return filters;
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

const enrichProviders = (
  providersResponse?: ProvidersApiResponse,
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
  }));
};

const getFilterValues = (
  searchParams: SearchParamsProps,
  key: string,
): string[] => {
  const rawValue = searchParams[`filter[${key}]`];

  if (!rawValue) {
    return [];
  }

  const filterValue = Array.isArray(rawValue) ? rawValue.join(",") : rawValue;
  return filterValue
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
};

const applyLocalFilters = ({
  organizationIds,
  providerGroupIds,
  providers,
}: ProvidersTableLocalFilters & { providers: ProvidersProviderRow[] }) => {
  return providers.filter((provider) => {
    const organizationId =
      provider.relationships.organization?.data?.id ?? null;
    const matchesOrganization =
      organizationIds.length === 0 ||
      organizationIds.includes(organizationId ?? "");
    const providerGroupIdsForProvider =
      provider.relationships.provider_groups.data.map(
        (providerGroup) => providerGroup.id,
      );
    const matchesGroup =
      providerGroupIds.length === 0 ||
      providerGroupIds.some((providerGroupId) =>
        providerGroupIdsForProvider.includes(providerGroupId),
      );

    return matchesOrganization && matchesGroup;
  });
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
}: {
  organizationId: string;
  organizationUnits: OrganizationUnitResource[];
  parentExternalId: string | null;
  parentOrganizationUnitId: string | null;
  providerLookup: Map<string, ProvidersProviderRow>;
  providersByOrganizationUnitId: Map<string, ProvidersProviderRow[]>;
  useParentIdRelationships: boolean;
}): ProvidersOrganizationRow[] {
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

  const organizationRows = organizations
    .map((organization) => {
      const organizationProvidersFromRelationships = getProviderRowsByIds({
        providerIds: getRelationshipProviderIds(organization.relationships),
        providerLookup,
      });
      const organizationProviders =
        organizationProvidersFromRelationships.length > 0
          ? organizationProvidersFromRelationships
          : (providersByOrganizationId.get(organization.id) ?? []);
      const organizationUnitRows = buildOrganizationUnitRows({
        organizationId: organization.id,
        organizationUnits,
        parentOrganizationUnitId: null,
        parentExternalId: organization.attributes.root_external_id,
        providerLookup,
        providersByOrganizationUnitId,
        useParentIdRelationships,
      });
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

  const localFilters = {
    organizationIds: getFilterValues(
      searchParams,
      PROVIDERS_PAGE_FILTER.ORGANIZATION,
    ),
    providerGroupIds: getFilterValues(
      searchParams,
      PROVIDERS_PAGE_FILTER.ACCOUNT_GROUP,
    ),
  };

  const providerFilters = { ...filters };

  // Map provider_type__in (used by ProviderTypeSelector) to provider__in (API param)
  const providerTypeFilter =
    providerFilters[`filter[${PROVIDERS_PAGE_FILTER.PROVIDER_TYPE}]`];
  if (providerTypeFilter) {
    providerFilters[`filter[${PROVIDERS_PAGE_FILTER.PROVIDER}]`] =
      providerTypeFilter;
  }

  // Remove client-side-only filters before sending to the API
  delete providerFilters[`filter[${PROVIDERS_PAGE_FILTER.PROVIDER_TYPE}]`];
  delete providerFilters[`filter[${PROVIDERS_PAGE_FILTER.ORGANIZATION}]`];
  delete providerFilters[`filter[${PROVIDERS_PAGE_FILTER.ACCOUNT_GROUP}]`];

  const emptyOrganizationsResponse: OrganizationListResponse = {
    data: [],
  };
  const emptyOrganizationUnitsResponse: OrganizationUnitListResponse = {
    data: [],
  };

  const [
    providersResponse,
    allProvidersResponse,
    providerGroupsResponse,
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
    // Unfiltered fetch for ProviderTypeSelector and AccountsSelector
    resolveActionResult(getProviders({ pageSize: 100 })),
    resolveActionResult(getProviderGroups({ page: 1, pageSize: 100 })),
    isCloud
      ? listOrganizationsSafe()
      : Promise.resolve(emptyOrganizationsResponse),
    isCloud
      ? listOrganizationUnitsSafe()
      : Promise.resolve(emptyOrganizationUnitsResponse),
  ]);

  const providers = applyLocalFilters({
    ...localFilters,
    providers: enrichProviders(providersResponse),
  });

  return {
    filters: createProvidersFilters({
      isCloud,
      organizations: organizationsResponse?.data ?? [],
      providerGroups: providerGroupsResponse?.data ?? [],
    }),
    metadata: providersResponse?.meta,
    providers: allProvidersResponse?.data ?? [],
    rows: buildProvidersTableRows({
      isCloud,
      organizations: organizationsResponse?.data ?? [],
      organizationUnits: organizationUnitsResponse?.data ?? [],
      providers,
    }),
  };
}

export { PROVIDERS_ROW_TYPE };
