"use client";

import { useSearchParams } from "next/navigation";
import { ComponentProps, useId } from "react";

import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { FilterSummaryStrip } from "@/components/filters/filter-summary-strip";
import { Badge, Tabs, TabsList, TabsTrigger } from "@/components/shadcn";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { VERDICT_TONE, VERDICTS, VerdictTone } from "@/lib/issues/verdicts";
import { cn } from "@/lib/utils";
import type { Verdict } from "@/types/issues";

interface VerdictSummary {
  counts: Record<Verdict, number>;
  /** Issues in scope, whatever their verdict. */
  total: number;
  /** Failed findings those issues fold. */
  findings: number;
}

const ALL_TAB = "all";

/** The active tab takes the verdict's colour instead of the default accent. */
const TONE_UNDERLINE: Record<VerdictTone, string> = {
  [VERDICT_TONE.fail]: "after:bg-bg-fail",
  [VERDICT_TONE.warning]: "after:bg-bg-data-medium",
  [VERDICT_TONE.pass]: "after:bg-bg-pass",
  [VERDICT_TONE.neutral]: "after:bg-bg-data-muted",
};

const TONE_BADGE: Record<VerdictTone, ComponentProps<typeof Badge>["variant"]> =
  {
    [VERDICT_TONE.fail]: "error",
    [VERDICT_TONE.warning]: "warning",
    [VERDICT_TONE.pass]: "success",
    [VERDICT_TONE.neutral]: "tag",
  };

/**
 * A combined verdict filter (the overview's "exploitable or likely" link)
 * selects no single tab, so the tabs it covers are marked by hand.
 */
const HIGHLIGHT = "text-slate-900 after:scale-x-100 dark:text-white";

/** Filters the issue list understands but no control on this page sets. */
const EXTRA_FILTER_LABELS = {
  "filter[pattern]": "Pattern",
  "filter[cloud]": "Cloud",
  "filter[severity]": "Severity",
  "filter[provider_type]": "Provider type",
  "filter[provider_alias]": "Account",
} as const;

export function VerdictFilter({ summary }: { summary?: VerdictSummary }) {
  const searchParams = useSearchParams();
  const { clearFilter, navigateWithParams } = useUrlFilters();
  const active = searchParams.get("filter[verdict]");
  const combined = searchParams.get("filter[verdict__in]")?.split(",") ?? [];
  const value = combined.length ? "" : (active ?? ALL_TAB);
  // No tab is selected under a combined filter, so the tab list says what
  // the list is showing.
  const combinedLabels = combined.map(
    (id) => VERDICTS.find((verdict) => verdict.id === id)?.label ?? id,
  );
  const descriptionId = useId();

  const handleChange = (next: string) => {
    navigateWithParams((params) => {
      params.delete("filter[verdict__in]");
      if (next === ALL_TAB) params.delete("filter[verdict]");
      else params.set("filter[verdict]", next);
    });
  };

  const tabs = [
    {
      id: ALL_TAB,
      label: "All",
      count: summary?.total,
      underline: "",
      badge: "tag" as const,
      highlighted: false,
    },
    ...VERDICTS.map(({ id, label, tone }) => ({
      id,
      label,
      count: summary?.counts[id],
      underline: TONE_UNDERLINE[tone],
      badge: TONE_BADGE[tone],
      highlighted: combined.includes(id),
    })),
  ];
  const chips = Object.entries(EXTRA_FILTER_LABELS).flatMap(([key, label]) => {
    const chipValue = searchParams.get(key);
    return chipValue ? [{ key, label, value: chipValue }] : [];
  });

  return (
    <div className="mb-6 flex flex-col gap-4">
      <Tabs value={value} onValueChange={handleChange}>
        <div className="flex flex-wrap items-center justify-between gap-x-6 gap-y-2">
          <div className="min-w-0 overflow-x-auto">
            {combinedLabels.length ? (
              <p id={descriptionId} className="sr-only">
                Showing {combinedLabels.join(" and ")} issues
              </p>
            ) : null}
            <TabsList
              aria-label="Filter issues by verdict"
              aria-describedby={
                combinedLabels.length ? descriptionId : undefined
              }
            >
              {tabs.map((tab) => (
                <TabsTrigger
                  key={tab.id}
                  value={tab.id}
                  data-highlighted={tab.highlighted || undefined}
                  className={cn(
                    "shrink-0",
                    tab.underline,
                    tab.highlighted && HIGHLIGHT,
                  )}
                  aria-label={
                    tab.count === undefined
                      ? undefined
                      : `${tab.label}, ${tab.count.toLocaleString()} ${tab.count === 1 ? "issue" : "issues"}`
                  }
                  adornment={
                    tab.count === undefined ? undefined : (
                      <Badge variant={tab.badge} size="sm">
                        {tab.count.toLocaleString()}
                      </Badge>
                    )
                  }
                >
                  {tab.label}
                </TabsTrigger>
              ))}
            </TabsList>
          </div>
          {summary ? (
            // The fold: how much noise the issue count removed.
            <p className="text-text-neutral-tertiary text-xs">
              {summary.findings.toLocaleString()} failed findings folded into{" "}
              {summary.total.toLocaleString()}{" "}
              {summary.total === 1 ? "issue" : "issues"}
            </p>
          ) : null}
        </div>
      </Tabs>
      {/* Only filters that arrived by link get a chip; the tabs and the scope
          selectors are their own controls, so they never need one. */}
      {chips.length ? (
        <FilterSummaryStrip
          chips={chips}
          onRemove={(key) => clearFilter(key)}
          trailingContent={<ClearFiltersButton />}
        />
      ) : null}
    </div>
  );
}
