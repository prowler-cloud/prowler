import { tool } from "@langchain/core/tools";
import { z } from "zod";

import {
  getFindingsBySeverity,
  getFindingsByStatus,
  getProvidersOverview,
} from "@/actions/overview/overview";
import {
  getFindingsBySeveritySchema,
  getFindingsByStatusSchema,
  getProvidersOverviewSchema,
} from "@/types/lighthouse";

export const getProvidersOverviewTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getProvidersOverviewSchema>;
    return await getProvidersOverview({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });
  },
  {
    name: "getProvidersOverview",
    description:
      "Retrieves an aggregated overview of findings and resources grouped by providers. The response includes the count of passed, failed, and manual findings, along with the total number of resources managed by each provider. Only the latest findings for each provider are considered in the aggregation to ensure accurate and up-to-date insights.",
    schema: getProvidersOverviewSchema,
  },
);

export const getFindingsByStatusTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getFindingsByStatusSchema>;
    return await getFindingsByStatus({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });
  },
  {
    name: "getFindingsByStatus",
    description:
      "Fetches aggregated findings data across all providers, grouped by various metrics such as passed, failed, muted, and total findings. This endpoint calculates summary statistics based on the latest scans for each provider and applies any provided filters, such as region, provider type, and scan date.",
    schema: getFindingsByStatusSchema,
  },
);

export const getFindingsBySeverityTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getFindingsBySeveritySchema>;
    return await getFindingsBySeverity({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });
  },
  {
    name: "getFindingsBySeverity",
    description:
      "Retrieves an aggregated summary of findings grouped by severity levels, such as low, medium, high, and critical. The response includes the total count of findings for each severity, considering only the latest scans for each provider. Additional filters can be applied to narrow down results by region, provider type, or other attributes.",
    schema: getFindingsBySeveritySchema,
  },
);
