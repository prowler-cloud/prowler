import { z } from "zod";

// Get Users Schema

const userFieldsEnum = z.enum([
  "",
  "name",
  "email",
  "company_name",
  "date_joined",
  "memberships",
  "roles",
]);

const sortFieldsEnum = z.enum([
  "",
  "name",
  "-name",
  "email",
  "-email",
  "company_name",
  "-company_name",
  "date_joined",
  "-date_joined",
  "is_active",
  "-is_active",
]);

const filtersSchema = z
  .object({
    // Fields selection
    "fields[users]": z
      .array(userFieldsEnum)
      .optional()
      .describe("Comma-separated list of user fields to include"),

    // String filters
    "filter[company_name]": z.string().optional(),
    "filter[company_name__icontains]": z.string().optional(),
    "filter[email]": z.string().optional(),
    "filter[email__icontains]": z.string().optional(),
    "filter[name]": z.string().optional(),
    "filter[name__icontains]": z.string().optional(),

    // Date filters
    "filter[date_joined]": z
      .string()
      .optional()
      .describe("Date in format YYYY-MM-DD"),
    "filter[date_joined__date]": z
      .string()
      .optional()
      .describe("Date in format YYYY-MM-DD"),
    "filter[date_joined__gte]": z
      .string()
      .optional()
      .describe("Date in format YYYY-MM-DD"),
    "filter[date_joined__lte]": z
      .string()
      .optional()
      .describe("Date in format YYYY-MM-DD"),

    // Boolean filters
    "filter[is_active]": z.boolean().optional(),
  })
  .partial();

export const getUsersSchema = z.object({
  page: z.number().int().describe("The page number to get. Default is 1."),
  query: z
    .string()
    .describe("The query to search for. Default is empty string."),
  sort: sortFieldsEnum.describe(
    "The sort order to use. Default is empty string.",
  ),
  filters: filtersSchema.describe(
    "The filters to apply. Default is empty object.",
  ),
});
