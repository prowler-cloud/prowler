import {
  adaptComplianceOverviewsResponse,
  getCompliancesOverview,
} from "@/actions/compliances";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { ComplianceWatchlist } from "./_components/compliance-watchlist";

export const ComplianceWatchlistSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const response = await getCompliancesOverview({ filters });
  const { data } = adaptComplianceOverviewsResponse(response);

  // Filter out ProwlerTHREATSCORE and limit to 5 items
  const items = data
    .filter((item) => item.framework !== "ProwlerTHREATSCORE")
    .slice(0, 5)
    .map((compliance) => ({
      id: compliance.id,
      framework: compliance.framework,
      label: compliance.label,
      icon: compliance.icon,
      score: compliance.score,
    }));

  return <ComplianceWatchlist items={items} />;
};
