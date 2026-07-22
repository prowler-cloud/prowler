"use client";

import { useRouter, useSearchParams } from "next/navigation";

import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Progress } from "@/components/shadcn/progress";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import type { ScoreColorVariant } from "@/lib/compliance/score-utils";
import { cn } from "@/lib/utils";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import { buildCrossProviderDetailHref } from "../_lib/cross-provider-frameworks";
import type { CrossProviderFrameworkSummary } from "../_types";

import { AggregatedFrameworkCard } from "./aggregated-framework-card";

export const CrossProviderFrameworkCard = ({
  complianceId,
  title,
  version,
  description,
  requirementsPassed,
  requirementsFailed,
  requirementsManual,
  totalRequirements,
  providerBreakdown,
}: CrossProviderFrameworkSummary) => {
  const router = useRouter();
  const searchParams = useSearchParams();

  const formattedTitle = `${title.split("-").join(" ")}${version ? ` - ${version}` : ""}`;

  const ratingPercentage =
    totalRequirements > 0
      ? Math.floor((requirementsPassed / totalRequirements) * 100)
      : 0;

  // Same thresholds as the per-scan ComplianceCard.
  const getRatingVariant = (value: number): ScoreColorVariant => {
    if (value <= 10) return "danger";
    if (value <= 40) return "warning";
    return "success";
  };

  const navigateToDetail = () => {
    router.push(
      buildCrossProviderDetailHref(
        { complianceId, title, version },
        Object.fromEntries(searchParams.entries()),
      ),
    );
  };

  return (
    <AggregatedFrameworkCard
      frameworkTitle={title}
      formattedTitle={formattedTitle}
      ariaLabel={formattedTitle}
      onActivate={navigateToDetail}
      tooltip={description}
      subtitle={
        <small className="truncate">
          <span className="mr-1 text-xs font-semibold">
            {requirementsPassed} / {totalRequirements}
          </span>
          Passing Requirements
        </small>
      }
    >
      <div className="flex flex-col gap-2">
        <div className="flex items-center justify-between gap-3 text-xs">
          <span className="text-text-neutral-secondary font-medium tracking-wider">
            Score:
          </span>
          <span className="text-text-neutral-secondary">
            {ratingPercentage}%
          </span>
        </div>
        <Progress
          aria-label="Cross-provider compliance score"
          value={ratingPercentage}
          variant={getRatingVariant(ratingPercentage)}
        />
      </div>

      <div className="flex items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-1.5">
          {providerBreakdown.map((entry) => (
            <Tooltip key={entry.provider}>
              <TooltipTrigger asChild>
                <span
                  data-testid={`provider-chip-${entry.provider}`}
                  data-unscanned={entry.unscanned || undefined}
                  className={cn(
                    "inline-flex items-center",
                    entry.unscanned && "opacity-35 grayscale",
                  )}
                >
                  <ProviderTypeIcon type={entry.provider} size={18} />
                </span>
              </TooltipTrigger>
              <TooltipContent>
                {PROVIDER_DISPLAY_NAMES[entry.provider]}
                {entry.unscanned
                  ? " — no completed scan yet"
                  : ` — ${entry.score}% passing`}
              </TooltipContent>
            </Tooltip>
          ))}
        </div>
        <span className="text-text-neutral-secondary text-xs whitespace-nowrap">
          {requirementsFailed} failed · {requirementsManual} manual
        </span>
      </div>
    </AggregatedFrameworkCard>
  );
};
