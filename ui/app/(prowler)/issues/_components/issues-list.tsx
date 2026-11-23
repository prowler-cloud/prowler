import { ReactNode } from "react";

import { getIssues, getIssuesOverview } from "@/actions/issues";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { IssuesSummary } from "@/components/issues/issues-summary";
import { IssuesTable } from "@/components/issues/issues-table";
import { VerdictFilter } from "@/components/issues/verdict-filter";
import { ISSUE_SCOPE_KEYS } from "@/lib/issues/scope";
import { verdictCounts, VERDICTS } from "@/lib/issues/verdicts";
import { SAMPLE_ACCOUNT } from "@/lib/sample-preview/sample-dataset";
import {
  SAMPLE_ISSUES,
  summarizeSampleIssues,
} from "@/lib/sample-preview/sample-issues";
import { SearchParamsProps } from "@/types";
import type { IssueResponse, IssuesOverviewResponse } from "@/types/issues";

/** Only the filters the issues endpoint understands are forwarded. */
const ISSUE_FILTER_KEYS = [
  "filter[verdict]",
  "filter[verdict__in]",
  "filter[cloud]",
  "filter[pattern]",
  "filter[severity]",
  "filter[provider_type]",
  "filter[provider_alias]",
  "filter[triage_status]",
  "filter[triage_status__in]",
  ...ISSUE_SCOPE_KEYS,
] as const;

export const IssuesList = async ({
  searchParams,
  filters: filterControls,
  providerUids,
  sample = false,
}: {
  searchParams: SearchParamsProps;
  /** Renders the sample issues instead of calling the issues API. */
  sample?: boolean;
  /** The scope selectors, rendered above the verdict tabs: they scope every tab. */
  filters?: ReactNode;
  /** Provider uid by provider id, for the issue panel. */
  providerUids?: Record<string, string>;
}) => {
  const filters: Record<string, string> = {};
  ISSUE_FILTER_KEYS.forEach((key) => {
    const value = searchParams[key];
    if (typeof value === "string" && value) filters[key] = value;
  });

  // The counts are deliberately NOT filtered by verdict: the ladder has to
  // keep showing every verdict's total, or picking one would zero the rest
  // and there would be no way back.
  const scope = Object.fromEntries(
    Object.entries(filters).filter(
      ([key]) => key !== "filter[verdict]" && key !== "filter[verdict__in]",
    ),
  );
  const [summary, issues] = sample
    ? sampleIssues(filters, scope, searchParams.sort)
    : await Promise.all([
        getIssuesOverview({ filters: scope }),
        getIssues({
          filters,
          page: Number(searchParams.page) || 1,
          pageSize: Number(searchParams.pageSize) || 10,
          sort:
            typeof searchParams.sort === "string"
              ? searchParams.sort
              : undefined,
        }),
      ]);

  const attributes = summary?.data?.attributes;
  // handleApiResponse resolves {error, status} on a 4xx and undefined on a
  // network failure; neither is an empty list.
  const rows = Array.isArray(issues?.data) ? issues.data : null;

  return (
    <>
      {attributes ? (
        <div className="mb-6">
          <IssuesSummary summary={attributes} />
        </div>
      ) : (
        <IssuesLoadError message="Failed to load issue summary." />
      )}

      {filterControls}

      <VerdictFilter
        summary={
          attributes
            ? {
                counts: verdictCounts(attributes),
                total: attributes.issues,
              }
            : undefined
        }
      />

      {rows === null ? (
        <IssuesLoadError />
      ) : rows.length ? (
        <IssuesTable
          issues={rows}
          metadata={issues?.meta}
          providerUids={providerUids}
        />
      ) : (
        <p className="text-text-neutral-tertiary text-sm">
          No issues match this filter.
        </p>
      )}
    </>
  );
};

type SampleIssue = (typeof SAMPLE_ISSUES)[number];

/** The value each forwarded filter matches on a sample issue. */
const SAMPLE_FILTER_FIELDS: Record<
  (typeof ISSUE_FILTER_KEYS)[number],
  (issue: SampleIssue) => string | undefined
> = {
  "filter[verdict]": (issue) => issue.attributes.verdict,
  "filter[verdict__in]": (issue) => issue.attributes.verdict,
  "filter[cloud]": (issue) => issue.attributes.cloud,
  "filter[pattern]": (issue) => issue.attributes.pattern,
  "filter[severity]": (issue) => issue.attributes.severity,
  "filter[provider_type]": (issue) => issue.attributes.cloud,
  "filter[provider_type__in]": (issue) => issue.attributes.cloud,
  "filter[provider_alias]": () => SAMPLE_ACCOUNT.alias,
  "filter[provider_id__in]": (issue) => issue.relationships?.provider?.data?.id,
  // The sample account belongs to no provider group.
  "filter[provider_groups__in]": () => undefined,
  "filter[triage_status]": (issue) => issue.attributes.triage_status,
  "filter[triage_status__in]": (issue) => issue.attributes.triage_status,
};

const matchesSampleFilters = (
  issue: SampleIssue,
  filters: Record<string, string>,
) =>
  Object.entries(filters).every(([key, value]) => {
    const field =
      SAMPLE_FILTER_FIELDS[key as keyof typeof SAMPLE_FILTER_FIELDS];
    const actual = field?.(issue);
    // Only `__in` filters take a list; the rest match one literal value.
    const accepted = key.endsWith("__in]") ? value.split(",") : [value];
    return actual !== undefined && accepted.includes(actual);
  });

/** The sample summary and rows, filtered like the API would. */
function sampleIssues(
  filters: Record<string, string>,
  scope: Record<string, string>,
  sort: SearchParamsProps["sort"],
): [IssuesOverviewResponse, IssueResponse] {
  const scoped = SAMPLE_ISSUES.filter((issue) =>
    matchesSampleFilters(issue, scope),
  );
  const rows = SAMPLE_ISSUES.filter((issue) =>
    matchesSampleFilters(issue, filters),
  );
  if (typeof sort === "string") {
    const descending = sort.startsWith("-");
    const field = descending ? sort.slice(1) : sort;
    if (field === "verdict_rank" || field === "findings_count") {
      const value = (issue: SampleIssue) =>
        field === "findings_count"
          ? issue.attributes.findings_count
          : VERDICTS.findIndex(({ id }) => id === issue.attributes.verdict);
      rows.sort((a, b) => (value(a) - value(b)) * (descending ? -1 : 1));
    }
  }
  return [
    {
      data: {
        type: "issues-overview",
        attributes: summarizeSampleIssues(scoped),
      },
    },
    {
      data: rows,
    },
  ];
}
