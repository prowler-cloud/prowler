import { tool } from "@langchain/core/tools";

import {
  aiGetComplianceOverview,
  aiGetCompliancesOverview,
} from "@/actions/lighthouse/compliances";
import { aiGetComplianceFrameworks } from "@/lib/lighthouse/helperComplianceFrameworks";
import {
  getComplianceFrameworksSchema,
  getComplianceOverviewSchema,
  getCompliancesOverviewSchema,
} from "@/types/lighthouse";

export const getCompliancesOverviewTool = tool(
  async ({ scanId, fields, filters, page, page_size, sort }) => {
    return await aiGetCompliancesOverview({
      scanId,
      fields,
      filters,
      page,
      page_size,
      sort,
    });
  },
  {
    name: "getCompliancesOverview",
    description:
      "Retrieves an overview of all the compliance in a given scan. If no region filters are provided, the region with the most fails will be returned by default.",
    schema: getCompliancesOverviewSchema,
  },
);

export const getComplianceFrameworksTool = tool(
  async ({ provider }) => {
    return await aiGetComplianceFrameworks(provider);
  },
  {
    name: "getComplianceFrameworks",
    description:
      "Retrieves the compliance frameworks for a given provider type.",
    schema: getComplianceFrameworksSchema,
  },
);

export const getComplianceOverviewTool = tool(
  async ({ complianceId, fields }) => {
    return await aiGetComplianceOverview({ complianceId, fields });
  },
  {
    name: "getComplianceOverview",
    description:
      "Retrieves the detailed compliance overview for a given compliance ID. The details are for individual compliance framework.",
    schema: getComplianceOverviewSchema,
  },
);
