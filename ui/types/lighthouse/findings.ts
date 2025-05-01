import { z } from "zod";

// Get Findings Schema

const deltaEnum = z.enum(["", "new", "changed"]);

const impactEnum = z.enum([
  "",
  "critical",
  "high",
  "medium",
  "low",
  "informational",
]);

const providerTypeEnum = z.enum(["", "aws", "azure", "gcp", "kubernetes"]);

const statusEnum = z.enum(["", "FAIL", "PASS", "MANUAL", "MUTED"]);

const sortFieldsEnum = z.enum([
  "",
  "status",
  "-status",
  "severity",
  "-severity",
  "check_id",
  "-check_id",
  "inserted_at",
  "-inserted_at",
  "updated_at",
  "-updated_at",
]);

export const getFindingsSchema = z.object({
  page: z.number().int().describe("The page number to get. Default is 1."),
  pageSize: z
    .number()
    .int()
    .describe("The number of findings to get per page. Default is 10."),
  query: z
    .string()
    .describe("The query to search for. Default is empty string."),
  sort: z
    .string(sortFieldsEnum)
    .describe("The sort order to use. Default is empty string."),
  filters: z
    .object({
      "filter[check_id]": z
        .string()
        .optional()
        .describe(
          "ID of checks supported for each provider. Use getProviderChecks tool to get the list of checks for a provider.",
        ),
      "filter[check_id__icontains]": z.string().optional(),
      "filter[check_id__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of check UUIDs"),

      // Delta filter
      "filter[delta]": deltaEnum.nullable().optional(),
      "filter[delta__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of UUID values"),

      // UUID filters
      "filter[id]": z.string().optional().describe("UUID"),
      "filter[id__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of UUID values"),

      // Impact and Severity filters
      "filter[impact]": impactEnum.optional(),
      "filter[impact__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of impact values"),
      "filter[severity]": z
        .enum(["critical", "high", "medium", "low", "informational"])
        .optional(),
      "filter[severity__in]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of severity values. Do not use it with severity filter.",
        ),

      // Date filters
      "filter[inserted_at]": z
        .string()
        .optional()
        .describe("Date in format YYYY-MM-DD"),
      "filter[inserted_at__date]": z
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

      // Provider filters
      "filter[provider]": z.string().optional().describe("Provider UUID"),
      "filter[provider__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider UUID values"),
      "filter[provider_alias]": z.string().optional(),
      "filter[provider_alias__icontains]": z.string().optional(),
      "filter[provider_alias__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider aliases"),
      "filter[provider_type]": providerTypeEnum.optional(),
      "filter[provider_type__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider types"),
      "filter[provider_uid]": z.string().optional(),
      "filter[provider_uid__icontains]": z.string().optional(),
      "filter[provider_uid__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider UIDs"),

      // Region filters
      "filter[region]": z.string().optional(),
      "filter[region__icontains]": z.string().optional(),
      "filter[region__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of region values"),

      // Resource filters
      "filter[resource_name]": z.string().optional(),
      "filter[resource_name__icontains]": z.string().optional(),
      "filter[resource_name__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of resource names"),
      "filter[resource_type]": z.string().optional(),
      "filter[resource_type__icontains]": z.string().optional(),
      "filter[resource_type__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of resource types"),
      "filter[resource_uid]": z.string().optional(),
      "filter[resource_uid__icontains]": z.string().optional(),
      "filter[resource_uid__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of resource UIDs"),
      "filter[resources]": z
        .string()
        .optional()
        .describe("Comma-separated list of resource UUID values"),

      // Scan filters
      "filter[scan]": z.string().optional().describe("Scan UUID"),
      "filter[scan__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of scan UUID values"),

      // Service filters
      "filter[service]": z.string().optional(),
      "filter[service__icontains]": z.string().optional(),
      "filter[service__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of service values"),

      // Status filters
      "filter[status]": statusEnum.optional(),
      "filter[status__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of status values"),

      // UID filters
      "filter[uid]": z.string().optional(),
      "filter[uid__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of UUID values"),

      // Updated at filters
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
    .optional()
    .describe(
      "The filters to apply. Default is {}. Only add necessary filters and ignore others. Generate the filters object **only** with non-empty values included.",
    ),
});

// Get Metadata Info Schema

export const getMetadataInfoSchema = z.object({
  query: z
    .string()
    .describe("The query to search for. Optional. Default is empty string."),
  sort: z
    .string()
    .describe("The sort order to use. Optional. Default is empty string."),
  filters: z
    .object({
      // Basic string filters
      "filter[check_id]": z.string().optional(),
      "filter[check_id__icontains]": z.string().optional(),
      "filter[check_id__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of check UUIDs"),

      // Delta filter
      "filter[delta]": deltaEnum.nullable().optional(),
      "filter[delta__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of UUID values"),

      // UUID filters
      "filter[id]": z.string().optional().describe("UUID"),
      "filter[id__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of UUID values"),

      // Impact and Severity filters
      "filter[impact]": impactEnum.optional(),
      "filter[impact__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of impact values"),
      "filter[severity]": z
        .enum(["critical", "high", "medium", "low", "informational"])
        .optional(),
      "filter[severity__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of severity values"),

      // Date filters
      "filter[inserted_at]": z
        .string()
        .optional()
        .describe("Date in format YYYY-MM-DD"),
      "filter[inserted_at__date]": z
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

      // Provider filters
      "filter[provider]": z.string().optional().describe("Provider UUID"),
      "filter[provider__in]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of provider UUID values. Use either provider or provider__in, not both.",
        ),
      "filter[provider_alias]": z.string().optional(),
      "filter[provider_alias__icontains]": z.string().optional(),
      "filter[provider_alias__in]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of provider aliases. Use either provider_alias or provider_alias__in, not both.",
        ),
      "filter[provider_type]": providerTypeEnum.optional(),
      "filter[provider_type__in]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of provider types. Use either provider_type or provider_type__in, not both.",
        ),
      "filter[provider_uid]": z.string().optional(),
      "filter[provider_uid__icontains]": z.string().optional(),
      "filter[provider_uid__in]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of provider UIDs. Use either provider_uid or provider_uid__in, not both.",
        ),

      // Region filters (excluding region__in)
      "filter[region]": z.string().optional(),
      "filter[region__icontains]": z.string().optional(),

      // Resource filters (excluding resource_type__in)
      "filter[resource_name]": z.string().optional(),
      "filter[resource_name__icontains]": z.string().optional(),
      "filter[resource_name__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of resource names"),
      "filter[resource_type]": z.string().optional(),
      "filter[resource_type__icontains]": z.string().optional(),
      "filter[resource_uid]": z.string().optional(),
      "filter[resource_uid__icontains]": z.string().optional(),
      "filter[resource_uid__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of resource UIDs"),
      "filter[resources]": z
        .string()
        .optional()
        .describe("Comma-separated list of resource UUID values"),

      // Scan filters
      "filter[scan]": z.string().optional().describe("Scan UUID"),
      "filter[scan__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of scan UUID values"),

      // Service filters (excluding service__in)
      "filter[service]": z.string().optional(),
      "filter[service__icontains]": z.string().optional(),

      // Status filters
      "filter[status]": statusEnum.optional(),
      "filter[status__in]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of status values. Use either status or status__in, not both.",
        ),

      // UID filters
      "filter[uid]": z.string().optional(),
      "filter[uid__in]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of UUID values. Use either uid or uid__in, not both.",
        ),

      // Updated at filters
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
    .partial()
    .describe(
      "The filters to apply. Optional. Default is empty object. Only add necessary filters and ignore others.",
    ),
});
