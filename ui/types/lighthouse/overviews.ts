import { z } from "zod";

// Get Providers Overview

export const getProvidersOverviewSchema = z.object({
  page: z
    .number()
    .int()
    .describe("The page number to get. Optional. Default is 1."),
  query: z
    .string()
    .describe("The query to search for. Optional. Default is empty string."),
  sort: z
    .string()
    .describe("The sort order to use. Optional. Default is empty string."),
  filters: z.object({}).describe("Always empty object."),
});

// Get Findings By Status

const providerTypeEnum = z.enum(["", "aws", "azure", "gcp", "kubernetes"]);

const sortFieldsEnum = z.enum([
  "",
  "id",
  "-id",
  "new",
  "-new",
  "changed",
  "-changed",
  "unchanged",
  "-unchanged",
  "fail_new",
  "-fail_new",
  "fail_changed",
  "-fail_changed",
  "pass_new",
  "-pass_new",
  "pass_changed",
  "-pass_changed",
  "muted_new",
  "-muted_new",
  "muted_changed",
  "-muted_changed",
  "total",
  "-total",
  "fail",
  "-fail",
  "muted",
  "-muted",
]);

export const getFindingsByStatusSchema = z.object({
  page: z
    .number()
    .int()
    .describe("The page number to get. Optional. Default is 1."),
  query: z
    .string()
    .describe("The query to search for. Optional. Default is empty string."),
  sort: sortFieldsEnum
    .optional()
    .describe("The sort order to use. Optional. Default is empty string."),
  filters: z
    .object({
      // Fields selection
      "fields[findings-overview]": z
        .string()
        .optional()
        .describe(
          "Comma-separated list of fields to include in the response. Default is empty string.",
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

      // Boolean filters
      "filter[muted_findings]": z
        .boolean()
        .optional()
        .describe("Default is empty string."),

      // Provider filters
      "filter[provider_id]": z.string().optional().describe("Provider ID"),
      "filter[provider_type]": providerTypeEnum.optional(),
      "filter[provider_type__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider types"),

      // Region filters
      "filter[region]": z.string().optional(),
      "filter[region__icontains]": z.string().optional(),
      "filter[region__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of regions"),

      // Search filter
      "filter[search]": z.string().optional(),
    })
    .partial()
    .describe("Use filters only when needed. Default is empty object."),
});

// Get Findings By Severity

export const getFindingsBySeveritySchema = z.object({
  page: z
    .number()
    .int()
    .describe("The page number to get. Optional. Default is 1."),
  query: z
    .string()
    .describe("The query to search for. Optional. Default is empty string."),
  sort: sortFieldsEnum.describe(
    "The sort order to use. Optional. Default is empty string.",
  ),
  filters: z
    .object({
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

      // Boolean filters
      "filter[muted_findings]": z
        .boolean()
        .optional()
        .describe("Default is empty string."),

      // Provider filters
      "filter[provider_id]": z
        .string()
        .optional()
        .describe("Valid provider UUID"),
      "filter[provider_type]": providerTypeEnum.optional(),
      "filter[provider_type__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of provider types"),

      // Region filters
      "filter[region]": z.string().optional(),
      "filter[region__icontains]": z.string().optional(),
      "filter[region__in]": z
        .string()
        .optional()
        .describe("Comma-separated list of regions"),

      // Search filter
      "filter[search]": z.string().optional(),
    })
    .partial()
    .describe("Use filters only when needed. Default is empty object."),
});
