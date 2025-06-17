import { z } from "zod";

// Get Providers Schema

const providerEnum = z.enum(["", "aws", "azure", "gcp", "kubernetes"]);

const sortFieldsEnum = z.enum([
  "",
  "provider",
  "-provider",
  "uid",
  "-uid",
  "alias",
  "-alias",
  "connected",
  "-connected",
  "inserted_at",
  "-inserted_at",
  "updated_at",
  "-updated_at",
]);

export const getProvidersSchema = z
  .object({
    page: z.number().describe("The page number to get. Default is 1."),
    query: z
      .string()
      .describe("The query to search for. Default is empty string."),
    sort: sortFieldsEnum.describe(
      "The sort order to use. Default is empty string.",
    ),
    filters: z
      .object({
        "filter[alias]": z.string().optional(),
        "filter[alias__icontains]": z.string().optional(),
        "filter[alias__in]": z
          .string()
          .optional()
          .describe("Comma-separated list of provider aliases"),

        "filter[connected]": z.boolean().optional().describe("Default True."),

        "filter[id]": z.string().optional().describe("Provider UUID"),
        "filter[id__in]": z
          .string()
          .optional()
          .describe("Comma-separated list of provider UUID values"),

        "filter[inserted_at]": z
          .string()
          .optional()
          .describe("Date in format YYYY-MM-DD"),
        "filter[inserted_at__gte]": z
          .string()
          .optional()
          .describe("Date in format YYYY-MM-DD"),
        "filter[inserted_at__lte]": z
          .string()
          .optional()
          .describe("Date in format YYYY-MM-DD"),

        "filter[provider]": providerEnum.optional(),
        "filter[provider__in]": z
          .string()
          .optional()
          .describe("Comma-separated list of provider types"),

        "filter[search]": z.string().optional(),

        "filter[uid]": z.string().optional(),
        "filter[uid__icontains]": z.string().optional(),
        "filter[uid__in]": z
          .string()
          .optional()
          .describe("Comma-separated list of provider UIDs"),

        "filter[updated_at]": z
          .string()
          .optional()
          .describe("Date in format YYYY-MM-DD"),
        "filter[updated_at__gte]": z
          .string()
          .optional()
          .describe("Date in format YYYY-MM-DD"),
        "filter[updated_at__lte]": z
          .string()
          .optional()
          .describe("Date in format YYYY-MM-DD"),
      })
      .describe(
        "The filters to apply. Optional. Don't use individual filters unless needed. Default is {}.",
      ),
  })
  .required();

// Get Provider Schema

export const getProviderSchema = z.object({
  id: z.string().describe("Provider UUID"),
});
