import { z } from "zod";

export const getRolesSchema = z.object({
  page: z.number().describe("The page number to get. Default is 1."),
  query: z
    .string()
    .describe("The query to search for. Default is empty string."),
  sort: z.string().describe("The sort order to use. Default is empty string."),
  filters: z
    .object({
      "filter[id]": z.string().optional().describe("Role UUID"),
      "filter[id__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of role UUID values"),
      "filter[inserted_at]": z.string().optional().describe("Date of creation"),
      "filter[inserted_at__gte]": z
        .string()
        .optional()
        .describe("Date of creation greater than or equal to"),
      "filter[inserted_at__lte]": z
        .string()
        .optional()
        .describe("Date of creation less than or equal to"),
      "filter[name]": z.string().optional().describe("Role name"),
      "filter[name__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of role name values"),
      "filter[permission_state]": z
        .string()
        .optional()
        .describe("Permission state"),
      "filter[updated_at]": z
        .string()
        .optional()
        .describe("Date of last update"),
      "filter[updated_at__gte]": z
        .string()
        .optional()
        .describe("Date of last update greater than or equal to"),
      "filter[updated_at__lte]": z
        .string()
        .optional()
        .describe("Date of last update less than or equal to"),
    })
    .describe("Use empty object if no filters are needed."),
});

export const getRoleSchema = z.object({
  id: z.string().describe("The UUID of the role to get."),
});
