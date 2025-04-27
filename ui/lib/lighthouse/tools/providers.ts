import { tool } from "@langchain/core/tools";

import { getProvider, getProviders } from "@/actions/providers";
import { getProviderSchema, getProvidersSchema } from "@/types/lighthouse";

export const getProvidersTool = tool(
  async ({ page, query, sort, filters }) => {
    return await getProviders({
      page: page,
      query: query,
      sort: sort,
      filters: filters,
    });
  },
  {
    name: "getProviders",
    description:
      "Retrieves a list of all providers with options for filtering by various criteria.",
    schema: getProvidersSchema,
  },
);

export const getProviderTool = tool(
  async ({ id }) => {
    const formData = new FormData();
    formData.append("id", id);
    return await getProvider(formData);
  },
  {
    name: "getProvider",
    description:
      "Fetches detailed information about a specific provider by their ID.",
    schema: getProviderSchema,
  },
);
