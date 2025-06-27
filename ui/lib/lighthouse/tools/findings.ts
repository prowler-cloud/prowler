import { tool } from "@langchain/core/tools";

import { getMetadataInfo } from "@/actions/findings";
import {
  getLighthouseFindings,
  getLighthouseLatestFindings,
} from "@/actions/lighthouse/findings";
import { getFindingsSchema, getMetadataInfoSchema } from "@/types/lighthouse";

export const getFindingsTool = tool(
  async ({ page, pageSize, query, sort, filters }) => {
    return await getLighthouseFindings({
      page,
      pageSize,
      query,
      sort,
      filters,
    });
  },
  {
    name: "getFindings",
    description:
      "Retrieves a list of all findings with options for filtering by various criteria.",
    schema: getFindingsSchema,
  },
);

export const getLatestFindingsTool = tool(
  async ({ page, pageSize, query, sort, filters }) => {
    return await getLighthouseLatestFindings({
      page,
      pageSize,
      query,
      sort,
      filters,
    });
  },
  {
    name: "getLatestFindings",
    description:
      "Retrieves a list of the latest findings from the latest scans of all providers with options for filtering by various criteria.",
    // getLatestFindings uses the same schema as getFindings
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
