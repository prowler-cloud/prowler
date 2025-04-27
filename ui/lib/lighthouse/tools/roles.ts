import { tool } from "@langchain/core/tools";

import { getRoleInfoById, getRoles } from "@/actions/roles";
import { getRoleSchema, getRolesSchema } from "@/types/lighthouse";

export const getRolesTool = tool(
  async ({ page, query, sort, filters }) => {
    return await getRoles({ page, query, sort, filters });
  },
  {
    name: "getRoles",
    description: "Get a list of roles.",
    schema: getRolesSchema,
  },
);

export const getRoleTool = tool(
  async ({ id }) => {
    return await getRoleInfoById(id);
  },
  {
    name: "getRole",
    description: "Get a role by UUID.",
    schema: getRoleSchema,
  },
);
