import type { MetaDataProps, ResourceProps, SearchParamsProps } from "@/types";

import { SAMPLE_ACCOUNT } from "./sample-dataset";
import {
  SAMPLE_FINDINGS,
  SAMPLE_RESOURCES,
  type SampleResource,
} from "./sample-records";

// /resources rows built from the sample records, so counts, filters and the
// resource drawer agree with the Findings and Overview samples.

const DEFAULT_PAGE_SIZE = 10;

const PROVIDER_DATA: ResourceProps["relationships"]["provider"]["data"] = {
  type: "providers",
  id: SAMPLE_ACCOUNT.providerId,
  attributes: {
    inserted_at: SAMPLE_ACCOUNT.scannedAt,
    updated_at: SAMPLE_ACCOUNT.scannedAt,
    provider: "aws",
    uid: SAMPLE_ACCOUNT.uid,
    alias: SAMPLE_ACCOUNT.alias,
    connection: { connected: true, last_checked_at: SAMPLE_ACCOUNT.scannedAt },
  },
  relationships: {
    secret: { data: { type: "provider-secrets", id: "sample-secret" } },
  },
  links: { self: "" },
};

const toRow = (resource: SampleResource): ResourceProps => {
  const findings = SAMPLE_FINDINGS.filter(
    (finding) => finding.resource.id === resource.id,
  );
  const failed = findings.filter((finding) => finding.status === "FAIL");
  return {
    type: "resources",
    id: resource.id,
    attributes: {
      inserted_at: SAMPLE_ACCOUNT.scannedAt,
      updated_at: SAMPLE_ACCOUNT.scannedAt,
      uid: resource.uid,
      name: resource.name,
      region: resource.region,
      service: resource.service,
      tags: {},
      type: resource.type,
      groups: Array.from(
        new Set(findings.map((finding) => finding.check.resourceGroup)),
      ),
      failed_findings_count: failed.length,
      details: null,
      partition: "aws",
      metadata: null,
    },
    relationships: {
      provider: { data: PROVIDER_DATA },
      findings: { meta: { count: failed.length }, data: [] },
    },
    links: { self: "" },
  };
};

const SAMPLE_RESOURCE_ROWS = SAMPLE_RESOURCES.map(toRow);

const unique = (values: string[]) => Array.from(new Set(values)).sort();

/** Filter bar options, derived from the rows the sample filters match. */
export const SAMPLE_RESOURCE_FILTER_OPTIONS = {
  regions: unique(SAMPLE_RESOURCES.map((resource) => resource.region)),
  services: unique(SAMPLE_RESOURCES.map((resource) => resource.service)),
  types: unique(SAMPLE_RESOURCES.map((resource) => resource.type)),
  groups: unique(
    SAMPLE_RESOURCE_ROWS.flatMap((row) => row.attributes.groups ?? []),
  ),
};

// The filters the /resources filter bar and the Overview cards set.
const RESOURCE_FILTERS: Record<string, (row: ResourceProps) => string[]> = {
  "filter[region__in]": (row) => [row.attributes.region],
  "filter[service__in]": (row) => [row.attributes.service],
  "filter[type__in]": (row) => [row.attributes.type],
  "filter[groups__in]": (row) => row.attributes.groups ?? [],
  "filter[provider_type__in]": () => ["aws"],
  "filter[provider_id__in]": () => [SAMPLE_ACCOUNT.providerId],
  "filter[provider__in]": () => [SAMPLE_ACCOUNT.providerId],
};

const SORTABLE_FIELDS = ["type", "region", "service"] as const;
type SortableField = (typeof SORTABLE_FIELDS)[number];

const isSortableField = (field: string): field is SortableField =>
  (SORTABLE_FIELDS as readonly string[]).includes(field);

const param = (searchParams: SearchParamsProps, key: string) => {
  const value = searchParams[key];
  return Array.isArray(value) ? value.join(",") : value;
};

const positiveInteger = (value: string | undefined, fallback: number) => {
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
};

/** The sample row a `?resourceId=` link opens, if it is one. */
export const getSampleResourceRow = (resourceId: string | undefined) =>
  SAMPLE_RESOURCE_ROWS.find((row) => row.id === resourceId) ?? null;

/** One page of sample resources for the URL's filters, search and sort. */
export const filterSampleResources = (
  searchParams: SearchParamsProps,
): { data: ResourceProps[]; metadata: MetaDataProps } => {
  const search = param(searchParams, "filter[search]")?.trim().toLowerCase();
  const active = Object.entries(RESOURCE_FILTERS).flatMap(([key, field]) => {
    const value = param(searchParams, key);
    return value ? [{ field, accepted: value.split(",") }] : [];
  });

  const rows = SAMPLE_RESOURCE_ROWS.filter(
    (row) =>
      (!search ||
        `${row.attributes.name} ${row.attributes.uid}`
          .toLowerCase()
          .includes(search)) &&
      active.every(({ field, accepted }) =>
        field(row).some((value) => accepted.includes(value)),
      ),
  );

  const sort = param(searchParams, "sort");
  const descending = sort?.startsWith("-") ?? false;
  const sortField = sort?.replace(/^-/, "") ?? "";
  if (isSortableField(sortField)) {
    rows.sort((a, b) => {
      const comparison = a.attributes[sortField].localeCompare(
        b.attributes[sortField],
      );
      return descending ? -comparison : comparison;
    });
  }

  const pageSize = positiveInteger(
    param(searchParams, "pageSize"),
    DEFAULT_PAGE_SIZE,
  );
  const pages = Math.max(1, Math.ceil(rows.length / pageSize));
  const page = Math.min(positiveInteger(param(searchParams, "page"), 1), pages);

  return {
    data: rows.slice((page - 1) * pageSize, page * pageSize),
    metadata: {
      pagination: { page, pages, count: rows.length },
      version: "v1",
    },
  };
};
