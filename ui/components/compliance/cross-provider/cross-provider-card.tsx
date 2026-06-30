"use client";

import { Check, Circle } from "lucide-react";
import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";

import { getComplianceIcon } from "@/components/icons/compliance/IconCompliance";
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

export interface CrossProviderCardProps {
  /** Universal framework id (e.g. ``csa_ccm_4.0``). Used as the
   *  ``filter[compliance_id]`` value when navigating to the detail page. */
  complianceId: string;
  /** Display title — the framework name (e.g. ``CSA-CCM``). Resolved by
   *  ``getComplianceIcon`` to pick the matching logo asset. */
  title: string;
  version: string;
  description?: string;
  /** Roll-up totals returned by the API. */
  requirementsPassed: number;
  totalRequirements: number;
  /** Provider keys (lowercase, e.g. "aws") that actually contributed scans
   *  to the aggregated view. Rendered as "active" chips on the card. */
  contributingProviders: string[];
  /** Catalogue of provider keys the universal framework declares checks
   *  for. Rendered as chips; the ones missing from
   *  ``contributingProviders`` are dimmed to signal "no scan yet". */
  compatibleProviders: string[];
}

const formatTitle = (title: string) => title.split("-").join(" ");

const getRatingVariant = (value: number): ScoreColorVariant => {
  if (value <= 10) return "danger";
  if (value <= 40) return "warning";
  return "success";
};

interface ProviderChipProps {
  providerKey: string;
  active: boolean;
}

const ProviderChip = ({ providerKey, active }: ProviderChipProps) => {
  const Icon = active ? Check : Circle;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5",
        "text-[10px] font-semibold tracking-wide uppercase",
        active
          ? "border-bg-pass/40 bg-bg-pass/10 text-bg-pass"
          : "border-border-neutral-secondary text-text-neutral-secondary",
      )}
      title={
        active
          ? `${providerKey.toUpperCase()}: scan available`
          : `${providerKey.toUpperCase()}: no scan yet`
      }
    >
      <Icon className="size-3 shrink-0" strokeWidth={active ? 3 : 2} />
      {providerKey}
    </span>
  );
};

export const CrossProviderCard: React.FC<CrossProviderCardProps> = ({
  complianceId,
  title,
  version,
  description,
  requirementsPassed,
  totalRequirements,
  contributingProviders,
  compatibleProviders,
}) => {
  const searchParams = useSearchParams();
  const router = useRouter();

  const ratingPercentage =
    totalRequirements > 0
      ? Math.floor((requirementsPassed / totalRequirements) * 100)
      : 0;

  const navigateToDetail = () => {
    const formattedTitleForUrl = encodeURIComponent(title);
    const path = `/compliance/${formattedTitleForUrl}`;
    const params = new URLSearchParams();

    params.set("complianceId", complianceId);
    params.set("version", version);
    params.set("mode", "cross-provider");

    // Preserve provider/region filters when drilling in.
    const region = searchParams.get("filter[region__in]");
    if (region) params.set("filter[region__in]", region);
    const providerType = searchParams.get("filter[provider_type__in]");
    if (providerType) params.set("filter[provider_type__in]", providerType);

    router.push(`${path}?${params.toString()}`);
  };

  // Sorted, de-duplicated provider chip list. ``compatible_providers`` is
  // authoritative; ``contributingProviders`` may include providers the
  // framework does not declare (when callers pin scans via filter[scan__in]).
  const contributingSet = new Set(
    contributingProviders.map((p) => p.toLowerCase()),
  );
  const allChips = Array.from(
    new Set([
      ...compatibleProviders.map((p) => p.toLowerCase()),
      ...contributingProviders.map((p) => p.toLowerCase()),
    ]),
  ).sort();

  return (
    <Card
      variant="base"
      padding="md"
      className="relative cursor-pointer transition-shadow hover:shadow-md"
      onClick={navigateToDetail}
    >
      <CardContent className="p-0">
        <div className="flex w-full flex-col gap-3">
          <div className="flex items-start gap-3">
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
                  <h4 className="text-small truncate leading-5 font-bold">
                    {formatTitle(title)}
                    {version ? ` - ${version}` : ""}
                  </h4>
                </TooltipTrigger>
                <TooltipContent>
                  {formatTitle(title)}
                  {version ? ` - ${version}` : ""}
                </TooltipContent>
              </Tooltip>
              {description && (
                <small className="text-text-neutral-secondary mt-0.5 line-clamp-2 text-xs">
                  {description}
                </small>
              )}
            </div>
          </div>

          <div className="flex flex-col gap-1">
            <div className="flex items-center justify-between gap-3 text-xs">
              <span className="text-text-neutral-secondary font-medium tracking-wider">
                Cross-Provider Score:
              </span>
              <span className="text-text-neutral-secondary font-semibold">
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
            <small className="mt-0.5 truncate">
              <span className="mr-1 text-xs font-semibold">
                {requirementsPassed} / {totalRequirements}
              </span>
              Passing Requirements
            </small>
          </div>

          {allChips.length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {allChips.map((providerKey) => (
                <ProviderChip
                  key={providerKey}
                  providerKey={providerKey}
                  active={contributingSet.has(providerKey)}
                />
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
};
