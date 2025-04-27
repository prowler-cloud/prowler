import { tool } from "@langchain/core/tools";

import {
  getLighthouseResourceById,
  getLighthouseResources,
} from "@/actions/lighthouse/resources";
import { getResourceSchema, getResourcesSchema } from "@/types/lighthouse";

export const getResourcesTool = tool(
  async ({ page, query, sort, filters, fields }) => {
    return await getLighthouseResources(page, query, sort, filters, fields);
  },
  {
    name: "getResources",
    description: "Fetches all resource information",
    schema: getResourcesSchema,
  },
);

export const getResourceTool = tool(
  async ({ id, fields, include }) => {
    return await getLighthouseResourceById(id, fields, include);
  },
  {
    name: "getResource",
    description: "Fetches information about a resource by its UUID.",
    schema: getResourceSchema,
  },
);
