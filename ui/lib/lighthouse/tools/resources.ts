import { tool } from "@langchain/core/tools";

import {
  getLighthouseLatestResources,
  getLighthouseResourceById,
  getLighthouseResources,
} from "@/actions/lighthouse/resources";
import { getResourceSchema, getResourcesSchema } from "@/types/lighthouse";

export const getResourcesTool = tool(
  async ({ page, query, sort, filters, fields }) => {
    return await getLighthouseResources({ page, query, sort, filters, fields });
  },
  {
    name: "getResources",
    description:
      "Retrieve a list of all resources found during scans with options for filtering by various criteria. Mandatory to pass in scan UUID.",
    schema: getResourcesSchema,
  },
);

export const getResourceTool = tool(
  async ({ id, fields, include }) => {
    return await getLighthouseResourceById({ id, fields, include });
  },
  {
    name: "getResource",
    description:
      "Fetch detailed information about a specific resource by their Prowler assigned UUID. A Resource is an object that is discovered by Prowler. It can be anything from a single host to a whole VPC.",
    schema: getResourceSchema,
  },
);

export const getLatestResourcesTool = tool(
  async ({ page, query, sort, filters, fields }) => {
    return await getLighthouseLatestResources({
      page,
      query,
      sort,
      filters,
      fields,
    });
  },
  {
    name: "getLatestResources",
    description:
      "Retrieve a list of the latest resources from the latest scans across all providers with options for filtering by various criteria.",
    schema: getResourcesSchema, // Schema is same as getResourcesSchema
  },
);
