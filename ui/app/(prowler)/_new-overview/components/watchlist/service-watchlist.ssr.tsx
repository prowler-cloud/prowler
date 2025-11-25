import { getServicesOverview, ServiceOverview } from "@/actions/overview";
import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { ServiceWatchlist } from "./service-watchlist";

export const ServiceWatchlistSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  const response = await getServicesOverview({ filters });

  const items: ServiceOverview[] = response?.data ?? [];

  return <ServiceWatchlist items={items} />;
};
