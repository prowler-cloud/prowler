import {
  adaptComplianceWatchlistResponse,
  getComplianceWatchlist,
} from "@/actions/overview/compliance-watchlist";
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { buildComplianceContext } from "@/lib/lighthouse/context/contributions";
import { isCloud } from "@/lib/shared/env";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";

import { ComplianceWatchlist } from "./_components/compliance-watchlist";

// Bounded so watchlist items stay within the shared context item budget.
const MAX_WATCHLIST_CONTEXT_ITEMS = 2;

export const ComplianceWatchlistSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);
  // The card is named after the watchlist, so where there is one it lists
  // exactly what the organization pinned — including nothing, when nobody has
  // curated it yet. Without this the endpoint answers with every framework that
  // has data, which is what made pinning a framework change nothing here.
  //
  // Cloud-only: the filter is a Cloud addition to a shared endpoint, so in OSS
  // the card keeps its previous meaning — every framework with data — and says
  // so in its empty state rather than blaming an uncurated watchlist that
  // cannot exist there.
  const isWatchlistFiltered = isCloud();
  const response = await getComplianceWatchlist({
    filters,
    inWatchlist: isWatchlistFiltered,
  });
  const enrichedData = adaptComplianceWatchlistResponse(response);

  // Nothing is dropped from a watchlist: it is a deliberate selection, and
  // hiding something the organization pinned is the bug this card had. The
  // unfiltered list is still a ranking of everything, so ProwlerThreatScore
  // stays out of it there, exactly as before.
  // Client handles sorting and limiting to display count
  const items = enrichedData
    .filter(
      (item) =>
        isWatchlistFiltered ||
        !item.complianceId.toLowerCase().includes("threatscore"),
    )
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
      <ComplianceWatchlist items={items} hasWatchlist={isWatchlistFiltered} />
    </>
  );
};
