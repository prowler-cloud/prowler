import { getServicesOverview, ServiceOverview } from "@/actions/overview";

import { pickFilterParams } from "../_lib/filter-params";
import { SSRComponentProps } from "../_types";
import { ServiceWatchlist } from "./_components/service-watchlist";

export const ServiceWatchlistSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  const response = await getServicesOverview({ filters });

  const items: ServiceOverview[] = response?.data ?? [];

  return <ServiceWatchlist items={items} />;
};
