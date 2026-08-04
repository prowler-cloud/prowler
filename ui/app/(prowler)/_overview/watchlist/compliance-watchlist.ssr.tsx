import {
  adaptComplianceWatchlistResponse,
  getComplianceWatchlist,
} from "@/actions/overview/compliance-watchlist";
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { buildComplianceContext } from "@/lib/lighthouse/context/contributions";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";

import { ComplianceWatchlist } from "./_components/compliance-watchlist";

// Bounded so watchlist items stay within the shared context item budget.
const MAX_WATCHLIST_CONTEXT_ITEMS = 2;

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

  const worstFrameworks = [...items]
    .sort((left, right) => left.score - right.score)
    .slice(0, MAX_WATCHLIST_CONTEXT_ITEMS);

  return (
    <>
      {worstFrameworks.map((item) => (
        <LighthouseContextContributor
          key={item.framework}
          contributorId={`overview-compliance-watchlist-${item.framework}`}
          item={buildComplianceContext({
            pathname: "/",
            id: `watchlist-${item.framework}`,
            framework: item.label,
            score: item.score,
          })}
        />
      ))}
      <ComplianceWatchlist items={items} />
    </>
  );
};
