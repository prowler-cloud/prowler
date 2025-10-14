import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getProvider, getProviders } from "@/actions/providers";
import { getProviderSchema, getProvidersSchema } from "@/types/lighthouse";

export const getProvidersTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getProvidersSchema>;
    return await getProviders({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
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
  async (input) => {
    const typedInput = input as z.infer<typeof getProviderSchema>;
    const formData = new FormData();
    formData.append("id", typedInput.id);
    return await getProvider(formData);
  },
  {
    name: "getProvider",
    description:
      "Fetches detailed information about a specific provider by their ID.",
    schema: getProviderSchema,
  },
);
