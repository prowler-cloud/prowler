import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getScan, getScans } from "@/actions/scans";
import { getScanSchema, getScansSchema } from "@/types/lighthouse";

export const getScansTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getScansSchema>;
    const scans = await getScans({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });

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
  async (input) => {
    const typedInput = input as z.infer<typeof getScanSchema>;
    return await getScan(typedInput.id);
  },
  {
    name: "getScan",
    description:
      "Fetches detailed information about a specific scan by its ID.",
    schema: getScanSchema,
  },
);
