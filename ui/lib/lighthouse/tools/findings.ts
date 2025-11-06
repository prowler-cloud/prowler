import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getFindings, getMetadataInfo } from "@/actions/findings";
import { getFindingsSchema, getMetadataInfoSchema } from "@/types/lighthouse";

export const getFindingsTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getFindingsSchema>;
    return await getFindings({
      page: typedInput.page,
      pageSize: typedInput.pageSize,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });
  },
  {
    name: "getFindings",
    description:
      "Retrieves a list of all findings with options for filtering by various criteria.",
    schema: getFindingsSchema,
  },
);

export const getMetadataInfoTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getMetadataInfoSchema>;
    return await getMetadataInfo({
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });
  },
  {
    name: "getMetadataInfo",
    description:
      "Fetches unique metadata values from a set of findings. This is useful for dynamic filtering.",
    schema: getMetadataInfoSchema,
  },
);
