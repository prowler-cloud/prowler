import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getRoleInfoById, getRoles } from "@/actions/roles";
import { getRoleSchema, getRolesSchema } from "@/types/lighthouse";

export const getRolesTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getRolesSchema>;
    return await getRoles({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });
  },
  {
    name: "getRoles",
    description: "Get a list of roles.",
    schema: getRolesSchema,
  },
);

export const getRoleTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getRoleSchema>;
    return await getRoleInfoById(typedInput.id);
  },
  {
    name: "getRole",
    description: "Get a role by UUID.",
    schema: getRoleSchema,
  },
);
