import type { JsonApiDocument, JsonApiResource } from "@/types/jsonapi";

export interface ComplianceCatalogEntryAttributes {
  compliance_id: string;
  /** `*` for universal frameworks, which are one card across every type. */
  provider_type: string;
  scope: string;
  provider_types: string[];
  framework: string;
  name: string;
  version: string;
  description: string;
  total_requirements: number;
  requirements_passed: number;
  requirements_failed: number;
  requirements_manual: number;
  score: number | null;
  has_data: boolean;
  in_watchlist: boolean;
  watchlist_entry_id: string | null;
}

export type ComplianceCatalogEntryResource =
  JsonApiResource<ComplianceCatalogEntryAttributes>;

export interface ComplianceCatalogPaginationMeta {
  page?: number;
  pages?: number;
  count?: number;
}

export interface ComplianceCatalogResponseMeta {
  pagination?: ComplianceCatalogPaginationMeta;
  total_entries?: number;
  watchlist_count?: number;
  eligible_provider_types?: string[];
}

export type ComplianceCatalogResponse = JsonApiDocument<
  ComplianceCatalogEntryResource[],
  ComplianceCatalogResponseMeta
>;

export interface ComplianceWatchlistBulkResponseMeta {
  added?: number;
  already_present?: number;
  removed?: number;
  not_present?: number;
  watchlist_count?: number;
}

export type ComplianceWatchlistBulkResponse = JsonApiDocument<
  unknown[],
  ComplianceWatchlistBulkResponseMeta
>;
