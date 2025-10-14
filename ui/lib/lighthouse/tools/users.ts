import { tool } from "@langchain/core/tools";
import { z } from "zod";

import { getUserInfo, getUsers } from "@/actions/users/users";
import { getUsersSchema } from "@/types/lighthouse";

const emptySchema = z.object({});

export const getUsersTool = tool(
  async (input) => {
    const typedInput = input as z.infer<typeof getUsersSchema>;
    return await getUsers({
      page: typedInput.page,
      query: typedInput.query,
      sort: typedInput.sort,
      filters: typedInput.filters,
    });
  },
  {
    name: "getUsers",
    description:
      "Retrieves a list of all users with options for filtering by various criteria.",
    schema: getUsersSchema,
  },
);

export const getMyProfileInfoTool = tool(
  async (_input) => {
    return await getUserInfo();
  },
  {
    name: "getMyProfileInfo",
    description:
      "Fetches detailed information about the current authenticated user.",
    schema: emptySchema,
  },
);
