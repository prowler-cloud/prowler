import { tool } from "@langchain/core/tools";
import { z } from "zod";

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
  async (input) => {
    const typedInput = input as z.infer<typeof getCompliancesOverviewSchema>;
    return await getLighthouseCompliancesOverview({
      scanId: typedInput.scanId,
      fields: typedInput.fields,
      filters: typedInput.filters,
      page: typedInput.page,
      pageSize: typedInput.pageSize,
      sort: typedInput.sort,
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
  async (input) => {
    const typedInput = input as z.infer<typeof getComplianceFrameworksSchema>;
    return await getLighthouseComplianceFrameworks(typedInput.providerType);
  },
  {
    name: "getComplianceFrameworks",
    description:
      "Retrieves the compliance frameworks for a given provider type.",
    schema: getComplianceFrameworksSchema,
  },
);

export const getComplianceOverviewTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getComplianceOverviewSchema>;
    return await getLighthouseComplianceOverview({
      complianceId: typedInput.complianceId,
      fields: typedInput.fields,
    });
  },
  {
    name: "getComplianceOverview",
    description:
      "Retrieves the detailed compliance overview for a given compliance ID. The details are for individual compliance framework.",
    schema: getComplianceOverviewSchema,
  },
);
