import { MetaDataProps } from "./components";
import { FilterOption } from "./filters";
import {
  OrganizationResource,
  OrganizationUnitResource,
} from "./organizations";
import { ProviderProps } from "./providers";

export const PROVIDERS_ROW_TYPE = {
  ORGANIZATION: "organization",
  PROVIDER: "provider",
} as const;

export type ProvidersRowType =
  (typeof PROVIDERS_ROW_TYPE)[keyof typeof PROVIDERS_ROW_TYPE];

export const PROVIDERS_GROUP_KIND = {
  ORGANIZATION: "organization",
  ORGANIZATION_UNIT: "organization-unit",
} as const;

export type ProvidersGroupKind =
  (typeof PROVIDERS_GROUP_KIND)[keyof typeof PROVIDERS_GROUP_KIND];

export const PROVIDERS_PAGE_FILTER = {
  PROVIDER: "provider__in",
  PROVIDER_TYPE: "provider_type__in",
  STATUS: "connected",
} as const;

export type ProvidersPageFilter =
  (typeof PROVIDERS_PAGE_FILTER)[keyof typeof PROVIDERS_PAGE_FILTER];

export interface ProviderTableRelationshipData {
  id: string;
  type: string;
}

export interface ProviderTableRelationshipRef {
  data: ProviderTableRelationshipData | null;
}

export type ProviderTableRelationships = ProviderProps["relationships"] & {
  organization?: ProviderTableRelationshipRef;
  organization_unit?: ProviderTableRelationshipRef;
  organizational_unit?: ProviderTableRelationshipRef;
};

export interface ProvidersProviderRow
  extends Omit<ProviderProps, "relationships"> {
  rowType: typeof PROVIDERS_ROW_TYPE.PROVIDER;
  relationships: ProviderTableRelationships;
  groupNames: string[];
  hasSchedule: boolean;
  subRows?: ProvidersTableRow[];
}

export interface ProvidersOrganizationRow {
  id: string;
  rowType: typeof PROVIDERS_ROW_TYPE.ORGANIZATION;
  groupKind: ProvidersGroupKind;
  name: string;
  externalId: string | null;
  parentExternalId: string | null;
  organizationId: string | null;
  providerCount: number;
  subRows: ProvidersTableRow[];
}

export type ProvidersTableRow = ProvidersOrganizationRow | ProvidersProviderRow;

export interface ProvidersTableRowsInput {
  isCloud: boolean;
  organizations: OrganizationResource[];
  organizationUnits: OrganizationUnitResource[];
  providers: ProvidersProviderRow[];
}

export interface ProvidersAccountsViewData {
  filters: FilterOption[];
  metadata?: MetaDataProps;
  providers: ProviderProps[];
  rows: ProvidersTableRow[];
}

export function isProvidersOrganizationRow(
  row: ProvidersTableRow,
): row is ProvidersOrganizationRow {
  return row.rowType === PROVIDERS_ROW_TYPE.ORGANIZATION;
}

export function isProvidersProviderRow(
  row: ProvidersTableRow,
): row is ProvidersProviderRow {
  return row.rowType === PROVIDERS_ROW_TYPE.PROVIDER;
}
