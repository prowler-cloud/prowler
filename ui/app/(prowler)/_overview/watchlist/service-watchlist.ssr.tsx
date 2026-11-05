import { getServicesOverview, ServiceOverview } from "@/actions/overview";
import { LighthouseContextContributor } from "@/components/lighthouse/context-contributor";
import { buildServiceSummaryContext } from "@/lib/lighthouse/context/contributions";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";

import { ServiceWatchlist } from "./_components/service-watchlist";

export const ServiceWatchlistSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const response = await getServicesOverview({ filters });

  const items: ServiceOverview[] = response?.data ?? [];

  const riskiestService = [...items]
    .sort((left, right) => right.attributes.fail - left.attributes.fail)
    .find((item) => item.attributes.fail > 0);

  return (
    <>
      {riskiestService ? (
        <LighthouseContextContributor
          contributorId="overview-service-watchlist"
          item={buildServiceSummaryContext({
            pathname: "/",
            service: riskiestService.id,
            failedFindingsCount: riskiestService.attributes.fail,
            total: riskiestService.attributes.total,
          })}
        />
      ) : null}
      <ServiceWatchlist items={items} />
    </>
  );
};
