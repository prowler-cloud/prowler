import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getProfileInfo, getUsers } from "@/actions/users/users";
import { getUsersSchema } from "@/types/ai";

export const getUsersTool = tool(
  async ({ page, query, sort, filters }) => {
    return await getUsers({ page, query, sort, filters });
  },
  {
    name: "getUsers",
    description:
      "Retrieves a list of all users with options for filtering by various criteria.",
    schema: getUsersSchema,
  },
);

export const getMyProfileInfoTool = tool(
  async () => {
    return await getProfileInfo();
  },
  {
    name: "getMyProfileInfo",
    description:
      "Fetches detailed information about the current authenticated user.",
    schema: z.object({}),
  },
);
