import { SearchParamsProps } from "@/types";

import { pickFilterParams } from "../../lib/filter-params";
import { RiskSeverityChartDetailSSR } from "./risk-severity-chart-detail.ssr";

export const RiskSeverityChartSSR = async ({
  searchParams,
}: {
  searchParams: SearchParamsProps | undefined | null;
}) => {
  const filters = pickFilterParams(searchParams);

  return <RiskSeverityChartDetailSSR searchParams={filters} />;
};
