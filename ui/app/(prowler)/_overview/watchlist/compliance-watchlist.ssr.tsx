import {
  adaptComplianceWatchlistResponse,
  getComplianceWatchlist,
} from "@/actions/overview/compliance-watchlist";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { ComplianceWatchlist } from "./_components/compliance-watchlist";

export const ComplianceWatchlistSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);
  const response = await getComplianceWatchlist({ filters });
  const enrichedData = adaptComplianceWatchlistResponse(response);

  // Filter out ProwlerThreatScore and pass all items to client
  // Client handles sorting and limiting to display count
  const items = enrichedData
    .filter((item) => !item.complianceId.toLowerCase().includes("threatscore"))
    .map((item) => ({
      id: item.id,
      framework: item.complianceId,
      label: item.label,
      icon: item.icon,
      score: item.score,
    }));

  return <ComplianceWatchlist items={items} />;
};
