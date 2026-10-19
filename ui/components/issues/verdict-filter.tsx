"use client";

import Link from "next/link";
import { useSearchParams } from "next/navigation";

import { ClearFiltersButton } from "@/components/filters/clear-filters-button";
import { FilterSummaryStrip } from "@/components/filters/filter-summary-strip";
import { Button } from "@/components/shadcn/button/button";
import { useUrlFilters } from "@/hooks/use-url-filters";
import { VERDICTS } from "@/lib/issues/verdicts";
import type { Verdict } from "@/types/issues";

interface VerdictSummary {
  counts: Record<Verdict, number>;
  total: number;
}

const EXTRA_FILTER_LABELS = {
  "filter[pattern]": "Pattern",
  "filter[cloud]": "Cloud",
  "filter[severity]": "Severity",
  "filter[provider_type]": "Provider type",
  "filter[provider_alias]": "Account",
  "filter[verdict__in]": "Verdicts",
} as const;

export function VerdictFilter({ summary }: { summary?: VerdictSummary }) {
  const searchParams = useSearchParams();
  const { clearFilter } = useUrlFilters();
  const active = searchParams.get("filter[verdict]");
  const multiple = searchParams.get("filter[verdict__in]");

  const hrefFor = (verdict: Verdict | null) => {
    const params = new URLSearchParams(searchParams.toString());
    params.delete("page");
    params.delete("filter[verdict__in]");
    if (verdict === null || active === verdict)
      params.delete("filter[verdict]");
    else params.set("filter[verdict]", verdict);
    return params.size ? `/issues?${params}` : "/issues";
  };

  const options = [
    { id: null, label: "All", count: summary?.total },
    ...VERDICTS.map(({ id, label }) => ({
      id,
      label,
      count: summary?.counts[id],
    })),
  ];
  const chips = Object.entries(EXTRA_FILTER_LABELS).flatMap(([key, label]) => {
    const value = searchParams.get(key);
    if (!value) return [];
    const displayValue =
      key === "filter[verdict__in]"
        ? value
            .split(",")
            .map(
              (id) =>
                VERDICTS.find((verdict) => verdict.id === id)?.label ?? id,
            )
            .join(", ")
        : value;
    return [{ key, label, value, displayValue }];
  });

  return (
    <div className="mb-6 flex flex-col gap-4">
      <div
        className="flex flex-wrap gap-2"
        role="group"
        aria-label="Filter issues by verdict"
      >
        {options.map((option) => {
          const isActive =
            !multiple &&
            (active === option.id || (!active && option.id === null));
          return (
            <Button
              key={option.id ?? "all"}
              asChild
              variant={isActive ? "default" : "outline"}
              size="sm"
            >
              <Link
                href={hrefFor(option.id)}
                aria-current={isActive ? "true" : undefined}
                scroll={false}
              >
                {option.label}
                {option.count === undefined ? "" : ` ${option.count}`}
              </Link>
            </Button>
          );
        })}
      </div>
      <FilterSummaryStrip
        chips={chips}
        onRemove={(key) => clearFilter(key)}
        trailingContent={<ClearFiltersButton />}
      />
    </div>
  );
}
