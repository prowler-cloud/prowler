"use client";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import { Progress } from "@/components/shadcn/progress";
import {
  getScoreColor,
  getScoreIndicatorClass,
} from "@/lib/compliance/score-utils";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import type { ProviderBreakdownEntry } from "../_types";

interface ProviderCoverageCardProps {
  breakdown: ProviderBreakdownEntry[];
}

/** Per-provider pass score for the cross-provider detail: one row per
 *  compatible provider, dimmed when no completed scan contributed. */
export const ProviderCoverageCard = ({
  breakdown,
}: ProviderCoverageCardProps) => {
  return (
    <Card variant="base" className="flex h-full min-h-[372px] flex-col">
      <CardHeader>
        <CardTitle>Provider Coverage</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        {breakdown.map((entry) => (
          <div
            key={entry.provider}
            data-testid={`coverage-row-${entry.provider}`}
            className={entry.unscanned ? "opacity-50" : undefined}
          >
            <div className="flex items-center justify-between gap-3 text-sm">
              <span className="flex min-w-0 items-center gap-2">
                <ProviderTypeIcon type={entry.provider} size={18} />
                <span className="truncate">
                  {PROVIDER_DISPLAY_NAMES[entry.provider]}
                </span>
              </span>
              {entry.unscanned ? (
                <span className="text-text-neutral-tertiary text-xs whitespace-nowrap">
                  No completed scan
                </span>
              ) : (
                <span className="text-text-neutral-secondary text-xs">
                  {entry.score}%
                </span>
              )}
            </div>
            {!entry.unscanned && (
              <div className="mt-1.5 flex items-center gap-3">
                <Progress
                  aria-label={`${PROVIDER_DISPLAY_NAMES[entry.provider]} passing score`}
                  value={entry.score}
                  className="border-border-neutral-secondary h-2 border"
                  indicatorClassName={getScoreIndicatorClass(
                    getScoreColor(entry.score),
                  )}
                />
                <span className="text-text-neutral-tertiary text-xs whitespace-nowrap">
                  {entry.pass}/{entry.pass + entry.fail} · {entry.manual} manual
                </span>
              </div>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
};
