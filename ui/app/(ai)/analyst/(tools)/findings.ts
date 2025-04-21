import { tool } from "@langchain/core/tools";

import { getFindings, getMetadataInfo } from "@/actions/findings";
import { getFindingsSchema, getMetadataInfoSchema } from "@/types/lighthouse";

export const getFindingsTool = tool(
  async ({ page, pageSize, query, sort, filters }) => {
    return await getFindings({ page, pageSize, query, sort, filters });
  },
  {
    name: "getFindings",
    description:
      "Retrieves a list of all findings with options for filtering by various criteria.",
    schema: getFindingsSchema,
  },
);

export const getMetadataInfoTool = tool(
  async ({ query, sort, filters }) => {
    return await getMetadataInfo({ query, sort, filters });
  },
  {
    name: "getMetadataInfo",
    description:
      "Fetches unique metadata values from a set of findings. This is useful for dynamic filtering.",
    schema: getMetadataInfoSchema,
  },
);
