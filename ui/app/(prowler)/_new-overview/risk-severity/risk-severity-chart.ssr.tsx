import { SSRComponentProps } from "../_types";
import { pickFilterParams } from "../_lib/filter-params";
import { RiskSeverityChartDetailSSR } from "./risk-severity-chart-detail.ssr";

export const RiskSeverityChartSSR = async ({
  searchParams,
}: SSRComponentProps) => {
  const filters = pickFilterParams(searchParams);

  return <RiskSeverityChartDetailSSR searchParams={filters} />;
};
