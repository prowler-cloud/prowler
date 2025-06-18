import { z } from "zod";

// Get Compliances Overview Schema
const getCompliancesOverviewFields = z.enum([
  "inserted_at",
  "compliance_id",
  "framework",
  "version",
  "requirements_status",
  "region",
  "provider_type",
  "scan",
  "url",
]);

const getCompliancesOverviewFilters = z.object({
  "filter[compliance_id]": z
    .string()
    .optional()
    .describe(
      "The compliance ID to get the compliances overview for (ex: iso27001_2013_aws).",
    ),
  "filter[compliance_id__icontains]": z
    .string()
    .optional()
    .describe("List of compliance IDs to get the compliances overview for."),
  "filter[framework]": z
    .string()
    .optional()
    .describe(
      "The framework to get the compliances overview for (ex: ISO27001)",
    ),
  "filter[framework__icontains]": z
    .string()
    .optional()
    .describe("List of frameworks to get the compliances overview for."),
  "filter[framework__iexact]": z
    .string()
    .optional()
    .describe("The exact framework to get the compliances overview for."),
  "filter[inserted_at]": z.string().optional(),
  "filter[inserted_at__date]": z.string().optional(),
  "filter[inserted_at__gte]": z.string().optional(),
  "filter[inserted_at__lte]": z.string().optional(),
  "filter[provider_type]": z.string().optional(),
  "filter[provider_type__in]": z.string().optional(),
  "filter[region]": z.string().optional(),
  "filter[region__icontains]": z.string().optional(),
  "filter[region__in]": z.string().optional(),
  "filter[search]": z.string().optional(),
  "filter[version]": z.string().optional(),
  "filter[version__icontains]": z.string().optional(),
});

const getCompliancesOverviewSort = z.enum([
  "inserted_at",
  "-inserted_at",
  "compliance_id",
  "-compliance_id",
  "framework",
  "-framework",
  "region",
  "-region",
]);

export const getCompliancesOverviewSchema = z.object({
  scanId: z
    .string()
    .describe(
      "(Mandatory) The ID of the scan to get the compliances overview for. ID is UUID.",
    ),
  fields: z
    .array(getCompliancesOverviewFields)
    .optional()
    .describe(
      "The fields to get from the compliances overview. If not provided, all fields will be returned.",
    ),
  filters: getCompliancesOverviewFilters
    .optional()
    .describe(
      "The filters to get the compliances overview for. If not provided, all regions will be returned by default.",
    ),
  page: z.number().optional().describe("Page number. Default is 1."),
  pageSize: z.number().optional().describe("Page size. Default is 10."),
  sort: getCompliancesOverviewSort
    .optional()
    .describe("Sort by field. Default is inserted_at."),
});

export const getComplianceFrameworksSchema = z.object({
  providerType: z
    .enum(["aws", "azure", "gcp", "kubernetes", "m365"])
    .describe("The provider type to get the compliance frameworks for."),
});

export const getComplianceOverviewSchema = z.object({
  complianceId: z
    .string()
    .describe(
      "The compliance ID to get the compliance overview for. ID is UUID and fetched from getCompliancesOverview tool for each provider.",
    ),
  fields: z
    .array(
      z.enum([
        "inserted_at",
        "compliance_id",
        "framework",
        "version",
        "requirements_status",
        "region",
        "provider_type",
        "scan",
        "url",
        "description",
        "requirements",
      ]),
    )
    .optional()
    .describe(
      "The fields to get from the compliance standard. If not provided, all fields will be returned.",
    ),
});
