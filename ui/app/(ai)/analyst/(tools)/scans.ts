import { tool } from "@langchain/core/tools";

import { getScan, getScans } from "@/actions/scans";
import { getScanSchema, getScansSchema } from "@/types/ai/scans";

export const getScansTool = tool(
  async ({ page, query, sort, filters }) => {
    console.log("=> Invoking getScansTool - ", { page, query, sort, filters });
    const scans = await getScans({ page, query, sort, filters });

    return scans;
  },
  {
    name: "getScans",
    description:
      "Retrieves a list of all scans with options for filtering by various criteria.",
    schema: getScansSchema,
  },
);

export const getScanTool = tool(
  async ({ id }) => {
    console.log("=> Invoking getScanTool - ", { id });
    return await getScan(id);
  },
  {
    name: "getScan",
    description:
      "Fetches detailed information about a specific scan by its ID.",
    schema: getScanSchema,
  },
);
