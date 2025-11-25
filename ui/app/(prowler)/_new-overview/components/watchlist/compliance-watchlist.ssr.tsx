import {
  adaptComplianceOverviewsResponse,
  getCompliancesOverview,
  sortCompliancesForWatchlist,
} from "@/actions/compliances";
import { SearchParamsProps } from "@/types";

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

  const response = await getCompliancesOverview({ filters });
  const { data } = adaptComplianceOverviewsResponse(response);
  const sorted = sortCompliancesForWatchlist(data, 9);

  const items = sorted.map((compliance) =>
    buildComplianceWatchlistItem({
      id: compliance.id,
      framework: compliance.framework,
      label: compliance.label,
      icon: compliance.icon,
      score: compliance.score,
    }),
  );

  return <ComplianceWatchlist items={items} />;
};
