import { WATCHLIST_SCOPE } from "@/types/compliance-watchlist";
import type { FindingComplianceFramework } from "@/types/compliance-watchlist";

import type { FindingComplianceFrameworksResponse } from "./finding-compliance-frameworks.types";

export const adaptFindingComplianceFrameworks = (
  response: FindingComplianceFrameworksResponse | undefined,
): FindingComplianceFramework[] => {
  const data = Array.isArray(response?.data) ? response.data : [];

  return data.map((resource) => {
    const attributes = resource.attributes;
    return {
      id: resource.id,
      complianceId: attributes.compliance_id,
      providerType: attributes.provider_type,
      // Anything the API does not label `universal` is provider-scoped, which
      // is also the safe reading of a response from an older API.
      scope:
        attributes.scope === WATCHLIST_SCOPE.UNIVERSAL
          ? WATCHLIST_SCOPE.UNIVERSAL
          : WATCHLIST_SCOPE.PROVIDER,
      framework: attributes.framework,
      // `name` falls back to the id server-side, so it is never empty; the
      // display name can be, for a framework the SDK exposes no metadata for.
      name: attributes.name,
      version: attributes.version,
      inWatchlist: attributes.in_watchlist === true,
    };
  });
};
