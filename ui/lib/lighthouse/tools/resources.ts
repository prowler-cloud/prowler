import { tool } from "@langchain/core/tools";
import { z } from "zod";

import {
  getLighthouseLatestResources,
  getLighthouseResourceById,
  getLighthouseResources,
} from "@/actions/lighthouse/resources";
import { getResourceSchema, getResourcesSchema } from "@/types/lighthouse";

export const getResourcesTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getResourcesSchema>;
    return await getLighthouseResources({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
      fields: typedInput.fields,
    });
  },
  {
    name: "getResources",
    description:
      "Retrieve a list of all resources found during scans with options for filtering by various criteria. Mandatory to pass in scan UUID.",
    schema: getResourcesSchema,
  },
);

export const getResourceTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getResourceSchema>;
    return await getLighthouseResourceById({
      id: typedInput.id,
      fields: typedInput.fields,
      include: typedInput.include,
    });
  },
  {
    name: "getResource",
    description:
      "Fetch detailed information about a specific resource by their Prowler assigned UUID. A Resource is an object that is discovered by Prowler. It can be anything from a single host to a whole VPC.",
    schema: getResourceSchema,
  },
);

export const getLatestResourcesTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getResourcesSchema>;
    return await getLighthouseLatestResources({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
      fields: typedInput.fields,
    });
  },
  {
    name: "getLatestResources",
    description:
      "Retrieve a list of the latest resources from the latest scans across all providers with options for filtering by various criteria.",
    schema: getResourcesSchema, // Schema is same as getResourcesSchema
  },
);
