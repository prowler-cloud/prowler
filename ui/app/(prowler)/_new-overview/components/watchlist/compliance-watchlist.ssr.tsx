import {
  adaptComplianceOverviewsResponse,
  getCompliancesOverview,
} from "@/actions/compliances";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { ComplianceWatchlist } from "./compliance-watchlist";

export const ComplianceWatchlistSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const response = await getCompliancesOverview({ filters });
  const { data } = adaptComplianceOverviewsResponse(response);

  // Filter out ProwlerThreatScore and limit to 9 items
  const items = data
    .filter((item) => item.framework !== "ProwlerThreatScore")
    .slice(0, 9)
    .map((compliance) => ({
      id: compliance.id,
      framework: compliance.framework,
      label: compliance.label,
      icon: compliance.icon,
      score: compliance.score,
    }));

  return <ComplianceWatchlist items={items} />;
};
