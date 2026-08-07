"use client";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { Progress } from "@/components/shadcn/progress";
import { getScoreColor } from "@/lib/compliance/score-utils";
import type { KnownProviderType } from "@/types/providers";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import type { ProviderBreakdownEntry } from "../_types";

/** Pre-labeled coverage row — the cross-account detail feeds one per
 *  account, with the fixed provider type as the icon. */
export interface CoverageRow {
  key: string;
  label: string;
  iconType: KnownProviderType;
  pass: number;
  fail: number;
  manual: number;
  score: number;
}

interface ProviderCoverageCardProps {
  /** Cross-provider breakdown (one row per scanned provider type). */
  breakdown?: ProviderBreakdownEntry[];
  /** Pre-labeled rows (cross-account: one per account). Wins over
   *  `breakdown` when both are given. */
  rows?: CoverageRow[];
  title?: string;
  emptyMessage?: string;
}

/** Per-column pass score for the cross-provider/cross-account details: one
 *  row per provider type (or account) with a completed scan. */
export const ProviderCoverageCard = ({
  breakdown,
  rows,
  title = "Provider Coverage",
  emptyMessage = "No scanned providers for this framework yet.",
}: ProviderCoverageCardProps) => {
  const resolvedRows: CoverageRow[] =
    rows ??
    (breakdown ?? [])
      .filter((entry) => !entry.unscanned)
      .map((entry) => ({
        key: entry.provider,
        label: PROVIDER_DISPLAY_NAMES[entry.provider],
        iconType: entry.provider,
        pass: entry.pass,
        fail: entry.fail,
        manual: entry.manual,
        score: entry.score,
      }));

  return (
    <Card variant="base">
      <div className="flex min-h-[340px] flex-col gap-6">
        <CardHeader>
          <CardTitle>{title}</CardTitle>
        </CardHeader>
        <CardContent>
          {/* Capped + scrollable so a long list never stretches the sibling
              chart cards in the same grid row. */}
          <div className="minimal-scrollbar flex max-h-[300px] flex-col gap-4 overflow-y-auto">
            {resolvedRows.length === 0 && (
              <p className="text-text-neutral-secondary text-sm">
                {emptyMessage}
              </p>
            )}
            {resolvedRows.map((entry) => (
              <div key={entry.key} data-testid={`coverage-row-${entry.key}`}>
                <div className="flex items-center justify-between gap-3 text-sm">
                  <span className="flex min-w-0 items-center gap-2">
                    <ProviderTypeIcon type={entry.iconType} size={18} />
                    <span className="truncate">{entry.label}</span>
                  </span>
                  <span className="text-text-neutral-secondary text-xs">
                    {entry.score}%
                  </span>
                </div>
                <div className="mt-1.5 flex items-center gap-3">
                  <Progress
                    aria-label={`${entry.label} passing score`}
                    value={entry.score}
                    variant={getScoreColor(entry.score)}
                  />
                  <span className="text-text-neutral-tertiary text-xs whitespace-nowrap">
                    {entry.pass}/{entry.pass + entry.fail} · {entry.manual}{" "}
                    manual
                  </span>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </div>
    </Card>
  );
};
