import { getCompliancesOverview } from "@/actions/compliances";
import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { SearchParamsProps } from "@/types";
import { ComplianceOverviewData } from "@/types/compliance";

import { pickFilterParams } from "../../lib/filter-params";
import {
  buildComplianceWatchlistItem,
  ComplianceWatchlist,
} from "./compliance-watchlist";

export const ComplianceWatchlistSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const compliancesResponse = await getCompliancesOverview({
    filters,
  });

  const items =
    Array.isArray(compliancesResponse?.data) &&
    (compliancesResponse.data as ComplianceOverviewData[]).length > 0
      ? (compliancesResponse.data as ComplianceOverviewData[])
          .slice(0, 8)
          .map((compliance) => {
            const { attributes, id } = compliance;
            const {
              framework,
              version,
              requirements_passed,
              total_requirements,
            } = attributes;

            const iconSrc = getComplianceIcon(framework);

            return buildComplianceWatchlistItem({
              id,
              framework,
              version,
              requirements_passed,
              total_requirements,
              icon: iconSrc,
            });
          })
      : [];

  return <ComplianceWatchlist items={items} />;
};
