import { z } from "zod";

const resourceFieldsEnum = z.enum([
  "",
  "inserted_at",
  "updated_at",
  "uid",
  "name",
  "region",
  "service",
  "tags",
  "provider",
  "findings",
  "url",
  "type",
]);

const resourceIncludeEnum = z.enum(["", "provider", "findings"]);

const resourceSortEnum = z.enum([
  "",
  "provider_uid",
  "-provider_uid",
  "uid",
  "-uid",
  "name",
  "-name",
  "region",
  "-region",
  "service",
  "-service",
  "type",
  "-type",
  "inserted_at",
  "-inserted_at",
  "updated_at",
  "-updated_at",
]);

const providerTypeEnum = z.enum(["", "aws", "gcp", "azure", "kubernetes"]);

export const getResourcesSchema = z.object({
  page: z.number().optional().describe("The page number to fetch."),
  query: z
    .string()
    .optional()
    .describe("The search query to filter resources."),
  sort: resourceSortEnum.optional().describe("The sort order to use."),
  filters: z
    .object({
      "filter[inserted_at]": z
        .string()
        .optional()
        .describe("The date to filter by."),
      "filter[inserted_at__gte]": z
        .string()
        .optional()
        .describe("Filter by date greater than or equal to."),
      "filter[inserted_at__lte]": z
        .string()
        .optional()
        .describe("Filter by date less than or equal to."),
      "filter[name]": z.string().optional().describe("Filter by name."),
      "filter[name__icontains]": z
        .string()
        .optional()
        .describe("Filter by substring."),
      "filter[provider]": z.string().optional().describe("Filter by provider."),
      "filter[provider__in]": z
        .string()
        .optional()
        .describe("Filter by provider in."),
      "filter[provider_alias]": z
        .string()
        .optional()
        .describe("Filter by provider alias."),
      "filter[provider_alias__icontains]": z
        .string()
        .optional()
        .describe("Filter by substring."),
      "filter[provider_alias__in]": z
        .string()
        .optional()
        .describe("Multiple values separated by commas."),
      "filter[provider_type]": providerTypeEnum
        .optional()
        .describe("Filter by provider type."),
      "filter[provider_type__in]": providerTypeEnum
        .optional()
        .describe("Filter by multiple provider types separated by commas."),
      "filter[provider_uid]": z
        .string()
        .optional()
        .describe("Filter by provider uid."),
      "filter[provider_uid__icontains]": z
        .string()
        .optional()
        .describe("Filter by substring."),
      "filter[provider_uid__in]": z
        .string()
        .optional()
        .describe("Filter by multiple provider uids separated by commas."),
      "filter[region]": z.string().optional().describe("Filter by region."),
      "filter[region__icontains]": z
        .string()
        .optional()
        .describe("Filter by region substring."),
      "filter[region__in]": z
        .string()
        .optional()
        .describe("Filter by multiple regions separated by commas."),
      "filter[service]": z.string().optional().describe("Filter by service."),
      "filter[service__icontains]": z
        .string()
        .optional()
        .describe("Filter by service substring."),
      "filter[service__in]": z
        .string()
        .optional()
        .describe("Filter by multiple services separated by commas."),
      "filter[tag]": z.string().optional().describe("Filter by tag."),
      "filter[tag_key]": z.string().optional().describe("Filter by tag key."),
      "filter[tag_value]": z
        .string()
        .optional()
        .describe("Filter by tag value."),
      "filter[tags]": z
        .string()
        .optional()
        .describe("Filter by multiple tags separated by commas."),
      "filter[type]": z.string().optional().describe("Filter by type."),
      "filter[type__in]": z
        .string()
        .optional()
        .describe("Filter by multiple types separated by commas."),
      "filter[uid]": z.string().optional().describe("Filter by uid."),
      "filter[uid__icontains]": z
        .string()
        .optional()
        .describe("Filter by substring."),
      "filter[updated_at]": z
        .string()
        .optional()
        .describe("The uid to filter by."),
      "filter[updated_at__gte]": z
        .string()
        .optional()
        .describe("The uid to filter by."),
      "filter[updated_at__lte]": z
        .string()
        .optional()
        .describe("The uid to filter by."),
    })
    .optional()
    .describe("The filters to apply to the resources."),
  fields: z
    .array(resourceFieldsEnum)
    .optional()
    .describe("The fields to include in the response."),
});

export const getResourceSchema = z.object({
  id: z.string().describe("The UUID of the resource to get."),
  fields: z
    .array(resourceFieldsEnum)
    .optional()
    .describe("The fields to include in the response."),
  include: z
    .array(resourceIncludeEnum)
    .optional()
    .describe("Other details to include in the response."),
});
