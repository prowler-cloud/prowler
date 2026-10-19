import { ReactNode } from "react";

import { getIssues, getIssuesOverview } from "@/actions/issues";
import { IssuesLoadError } from "@/components/issues/issues-load-error";
import { IssuesTable } from "@/components/issues/issues-table";
import { VerdictFilter } from "@/components/issues/verdict-filter";
import { ISSUE_SCOPE_KEYS } from "@/lib/issues/scope";
import { verdictCounts } from "@/lib/issues/verdicts";
import { SearchParamsProps } from "@/types";

/** Only the filters the issues endpoint understands are forwarded. */
const ISSUE_FILTER_KEYS = [
  "filter[verdict]",
  "filter[verdict__in]",
  "filter[cloud]",
  "filter[pattern]",
  "filter[severity]",
  "filter[provider_type]",
  "filter[provider_alias]",
  ...ISSUE_SCOPE_KEYS,
];

export const IssuesList = async ({
  searchParams,
  filters: filterControls,
}: {
  searchParams: SearchParamsProps;
  /** The scope selectors, rendered above the verdict tabs: they scope every tab. */
  filters?: ReactNode;
}) => {
  const filters: Record<string, string> = {};
  ISSUE_FILTER_KEYS.forEach((key) => {
    const value = searchParams[key];
    if (typeof value === "string" && value) filters[key] = value;
  });

  const [summary, issues] = await Promise.all([
    // The counts are deliberately NOT filtered by verdict: the ladder has to
    // keep showing every verdict's total, or picking one would zero the rest
    // and there would be no way back.
    getIssuesOverview({
      filters: Object.fromEntries(
        Object.entries(filters).filter(
          ([key]) => key !== "filter[verdict]" && key !== "filter[verdict__in]",
        ),
      ),
    }),
    getIssues({
      filters,
      page: Number(searchParams.page) || 1,
      pageSize: Number(searchParams.pageSize) || 10,
      sort:
        typeof searchParams.sort === "string" ? searchParams.sort : undefined,
    }),
  ]);

  const attributes = summary?.data?.attributes;
  // handleApiResponse resolves {error, status} on a 4xx and undefined on a
  // network failure; neither is an empty list.
  const rows = Array.isArray(issues?.data) ? issues.data : null;

  return (
    <>
      {attributes ? null : (
        <IssuesLoadError message="Failed to load issue summary." />
      )}

      {filterControls}

      <VerdictFilter
        summary={
          attributes
            ? {
                counts: verdictCounts(attributes),
                total: attributes.issues,
                findings: attributes.findings,
              }
            : undefined
        }
      />

      {rows === null ? (
        <IssuesLoadError />
      ) : rows.length ? (
        <IssuesTable issues={rows} metadata={issues?.meta} />
      ) : (
        <p className="text-text-neutral-tertiary text-sm">
          No issues match this filter.
        </p>
      )}
    </>
  );
};
