import type {
  ComplianceCatalog,
  ComplianceCatalogEntry,
  ComplianceCatalogMeta,
  ComplianceWatchlistBulkSummary,
} from "@/types/compliance-watchlist";
import { WATCHLIST_SCOPE } from "@/types/compliance-watchlist";

import type {
  ComplianceCatalogEntryResource,
  ComplianceCatalogResponse,
  ComplianceWatchlistBulkResponse,
} from "./compliance-watchlist.types";

const EMPTY_META: ComplianceCatalogMeta = {
  totalEntries: 0,
  watchlistCount: 0,
  eligibleProviderTypes: [],
};

export const adaptCatalogEntry = (
  resource: ComplianceCatalogEntryResource,
): ComplianceCatalogEntry => {
  const attributes = resource.attributes;
  return {
    id: resource.id,
    complianceId: attributes.compliance_id,
    providerType: attributes.provider_type,
    // Anything the API does not label `universal` is a provider-scoped card,
    // which is also the safe reading of a response from an older API.
    scope:
      attributes.scope === WATCHLIST_SCOPE.UNIVERSAL
        ? WATCHLIST_SCOPE.UNIVERSAL
        : WATCHLIST_SCOPE.PROVIDER,
    providerTypes: Array.isArray(attributes.provider_types)
      ? attributes.provider_types
      : [attributes.provider_type],
    framework: attributes.framework,
    name: attributes.name,
    version: attributes.version,
    description: attributes.description,
    totalRequirements: attributes.total_requirements,
    requirementsPassed: attributes.requirements_passed,
    requirementsFailed: attributes.requirements_failed,
    requirementsManual: attributes.requirements_manual,
    // `score` stays null for a never-scanned framework so the card can render
    // "not scanned yet" instead of a red 0%.
    score: attributes.score ?? null,
    hasData: attributes.has_data === true,
    inWatchlist: attributes.in_watchlist === true,
    watchlistEntryId: attributes.watchlist_entry_id ?? null,
  };
};

export const adaptCatalogResponse = (
  response: ComplianceCatalogResponse | undefined,
): ComplianceCatalog => {
  const data = Array.isArray(response?.data) ? response.data : [];
  const meta = response?.meta;
  return {
    entries: data.map(adaptCatalogEntry),
    meta: {
      totalEntries: meta?.total_entries ?? 0,
      watchlistCount: meta?.watchlist_count ?? 0,
      eligibleProviderTypes: meta?.eligible_provider_types ?? [],
    },
  };
};

/** The catalog is paginated (10 per page by default, 100 max), so a tenant
 *  with several provider types needs more than one request. Root meta is
 *  identical on every page — counted before filtering — so the first page's
 *  copy is authoritative. */
export const mergeCatalogPages = (
  pages: ComplianceCatalog[],
): ComplianceCatalog => ({
  entries: pages.flatMap((page) => page.entries),
  meta: pages[0]?.meta ?? EMPTY_META,
});

export const adaptWatchlistBulkSummary = (
  response: ComplianceWatchlistBulkResponse | undefined,
): ComplianceWatchlistBulkSummary => {
  const meta = response?.meta;
  return {
    added: meta?.added ?? 0,
    alreadyPresent: meta?.already_present ?? 0,
    removed: meta?.removed ?? 0,
    notPresent: meta?.not_present ?? 0,
    watchlistCount: meta?.watchlist_count ?? 0,
  };
};
