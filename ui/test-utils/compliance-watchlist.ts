import type { ComplianceCatalogEntry } from "@/types/compliance-watchlist";
import {
  UNIVERSAL_PROVIDER_TYPE,
  WATCHLIST_SCOPE,
} from "@/types/compliance-watchlist";

type CatalogEntryOverrides = Partial<ComplianceCatalogEntry> &
  Pick<ComplianceCatalogEntry, "complianceId" | "providerType">;

export const makeComplianceCatalogEntry = ({
  complianceId,
  providerType,
  ...overrides
}: CatalogEntryOverrides): ComplianceCatalogEntry => {
  const inWatchlist = overrides.inWatchlist ?? false;

  return {
    id: `${providerType}:${complianceId}`,
    complianceId,
    providerType,
    scope:
      providerType === UNIVERSAL_PROVIDER_TYPE
        ? WATCHLIST_SCOPE.UNIVERSAL
        : WATCHLIST_SCOPE.PROVIDER,
    providerTypes:
      providerType === UNIVERSAL_PROVIDER_TYPE
        ? ["aws", "azure", "gcp"]
        : [providerType],
    framework: complianceId,
    name: complianceId,
    version: "1.0",
    description: "",
    totalRequirements: 10,
    requirementsPassed: 5,
    requirementsFailed: 5,
    requirementsManual: 0,
    score: 50,
    hasData: true,
    inWatchlist,
    watchlistEntryId: inWatchlist ? "entry-1" : null,
    ...overrides,
  };
};
