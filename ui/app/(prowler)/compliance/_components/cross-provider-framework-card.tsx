"use client";

import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
import { ProviderTypeIcon } from "@/components/icons/providers-badge/provider-type-icon";
import { Card, CardContent } from "@/components/shadcn/card/card";
import { Progress } from "@/components/shadcn/progress";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import {
  getScoreIndicatorClass,
  type ScoreColorVariant,
} from "@/lib/compliance/score-utils";
import { cn } from "@/lib/utils";
import { PROVIDER_DISPLAY_NAMES } from "@/types/providers";

import { buildCrossProviderDetailHref } from "../_lib/cross-provider-frameworks";
import type { ProviderBreakdownEntry } from "../_types";

interface CrossProviderFrameworkCardProps {
  complianceId: string;
  title: string;
  version: string;
  description: string;
  requirementsPassed: number;
  requirementsFailed: number;
  requirementsManual: number;
  totalRequirements: number;
  providerBreakdown: ProviderBreakdownEntry[];
}

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
}: CrossProviderFrameworkCardProps) => {
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
        { complianceId, title, version, description, compatibleProviders: [] },
        Object.fromEntries(searchParams.entries()),
      ),
    );
  };

  return (
    <Card
      variant="base"
      padding="md"
      className="relative cursor-pointer transition-shadow hover:shadow-md"
      onClick={navigateToDetail}
      role="button"
      aria-label={formattedTitle}
      tabIndex={0}
      onKeyDown={(event) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          navigateToDetail();
        }
      }}
    >
      <CardContent className="p-0">
        <div className="flex w-full flex-col gap-3">
          <div className="flex items-center gap-3">
            {getComplianceIcon(title) && (
              <div className="flex h-10 w-10 min-w-10 shrink-0 items-center justify-center rounded-md border border-gray-300 bg-white">
                <Image
                  src={getComplianceIcon(title)}
                  alt={`${title} logo`}
                  width={32}
                  height={32}
                  className="h-8 w-8 object-contain"
                />
              </div>
            )}
            <div className="flex min-w-0 flex-1 flex-col">
              <Tooltip>
                <TooltipTrigger asChild>
                  <h4 className="truncate text-sm leading-5 font-bold">
                    {formattedTitle}
                  </h4>
                </TooltipTrigger>
                <TooltipContent>{description}</TooltipContent>
              </Tooltip>
              <small className="truncate">
                <span className="mr-1 text-xs font-semibold">
                  {requirementsPassed} / {totalRequirements}
                </span>
                Passing Requirements
              </small>
            </div>
          </div>

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
              className="border-border-neutral-secondary h-2.5 border drop-shadow-sm"
              indicatorClassName={getScoreIndicatorClass(
                getRatingVariant(ratingPercentage),
              )}
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
        </div>
      </CardContent>
    </Card>
  );
};
