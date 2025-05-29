import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getUserInfo, getUsers } from "@/actions/users/users";
import { getUsersSchema } from "@/types/lighthouse";

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
    return await getUserInfo();
  },
  {
    name: "getMyProfileInfo",
    description:
      "Fetches detailed information about the current authenticated user.",
    schema: z.object({}),
  },
);
