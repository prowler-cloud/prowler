import { tool } from "@langchain/core/tools";

import { getLighthouseComplianceFrameworks } from "@/actions/lighthouse/complianceframeworks";
import {
  getLighthouseComplianceOverview,
  getLighthouseCompliancesOverview,
} from "@/actions/lighthouse/compliances";
import {
  getComplianceFrameworksSchema,
  getComplianceOverviewSchema,
  getCompliancesOverviewSchema,
} from "@/types/lighthouse";

export const getCompliancesOverviewTool = tool(
  async ({ scanId, fields, filters, page, pageSize, sort }) => {
    return await getLighthouseCompliancesOverview({
      scanId,
      fields,
      filters,
      page,
      pageSize,
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
  async ({ providerType }) => {
    return await getLighthouseComplianceFrameworks(providerType);
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
    return await getLighthouseComplianceOverview({ complianceId, fields });
  },
  {
    name: "getComplianceOverview",
    description:
      "Retrieves the detailed compliance overview for a given compliance ID. The details are for individual compliance framework.",
    schema: getComplianceOverviewSchema,
  },
);
