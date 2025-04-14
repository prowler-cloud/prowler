import { z } from "zod";

const providerTypeEnum = z.enum(["", "aws", "azure", "gcp", "kubernetes"]);
const stateEnum = z.enum([
  "",
  "available",
  "cancelled",
  "completed",
  "executing",
  "failed",
  "scheduled",
]);
const triggerEnum = z.enum(["", "manual", "scheduled"]);

const getScansSortEnum = z.enum([
  "",
  "name",
  "-name",
  "trigger",
  "-trigger",
  "scheduled_at",
  "-scheduled_at",
  "inserted_at",
  "-inserted_at",
  "updated_at",
  "-updated_at",
]);

// Get Scans Schema
export const getScansSchema = z.object({
  page: z.number().describe("The page number to get. Default is 1."),
  query: z
    .string()
    .describe("The query to search for. Default is empty string."),
  sort: z
    .string(getScansSortEnum)
    .describe("The sort order to use. Default is empty string."),
  filters: z
    .object({
      // Date filters
      "filter[completed_at]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),
      "filter[inserted_at]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),
      "filter[started_at]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),
      "filter[started_at__gte]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),
      "filter[started_at__lte]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),

      // Next scan filters
      "filter[next_scan_at]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),
      "filter[next_scan_at__gte]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),
      "filter[next_scan_at__lte]": z
        .string()
        .optional()
        .describe("ISO 8601 datetime string"),

      // Name filters
      "filter[name]": z.string().optional(),
      "filter[name__icontains]": z.string().optional(),

      // Provider filters
      "filter[provider]": z.string().optional().describe("Provider UUID"),
      "filter[provider__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider UUIDs"),

      // Provider alias filters
      "filter[provider_alias]": z.string().optional(),
      "filter[provider_alias__icontains]": z.string().optional(),
      "filter[provider_alias__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider aliases"),

      // Provider type filters
      "filter[provider_type]": providerTypeEnum.optional(),
      "filter[provider_type__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of values"),

      // Provider UID filters
      "filter[provider_uid]": z.string().optional(),
      "filter[provider_uid__icontains]": z.string().optional(),
      "filter[provider_uid__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of values"),

      // State filters
      "filter[state]": stateEnum.optional(),
      "filter[state__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of values"),

      // Trigger filter
      "filter[trigger]": triggerEnum
        .optional()
        .describe("Options are manual and scheduled"),

      // Search filter
      "filter[search]": z.string().optional(),
    })
    .describe(
      "Used to filter the scans. Use filters only if you need to filter the scans. Don't add date filters unless the user asks for it. Default is {}.",
    ),
});

// Get Scan Schema
export const getScanSchema = z.object({
  id: z.string().describe("Scan UUID"),
});
