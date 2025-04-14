import { tool } from "@langchain/core/tools";

import { aiGetResource, aiGetResources } from "@/actions/lighthouse/resources";
import { getResourceSchema, getResourcesSchema } from "@/types/ai/resources";

export const getResourcesTool = tool(
  async ({ page, query, sort, filters, fields }) => {
    console.log("=> Invoking getResourcesTool - ", {
      page,
      query,
      sort,
      filters,
      fields,
    });
    return await aiGetResources(page, query, sort, filters, fields);
  },
  {
    name: "getResources",
    description: "Fetches all resource information",
    schema: getResourcesSchema,
  },
);

export const getResourceTool = tool(
  async ({ id, fields, include }) => {
    console.log("=> Invoking getResourceTool - ", { id, fields, include });
    return await aiGetResource(id, fields, include);
  },
  {
    name: "getResource",
    description: "Fetches information about a resource by its UUID.",
    schema: getResourceSchema,
  },
);
