"use client";

import { MessageCircleWarning, ThumbsUp } from "lucide-react";

import type {
  CriticalRequirement,
  SectionScores,
} from "@/actions/overview/types";
import { RadialChart } from "@/components/graphs/radial-chart";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
  Skeleton,
} from "@/components/shadcn";

const THREAT_LEVEL_CONFIG = {
  DANGER: {
    label: "Critical Risk",
    color: "var(--bg-fail-primary)",
    chartColor: "var(--bg-fail-primary)",
    minScore: 0,
    maxScore: 30,
  },
  WARNING: {
    label: "Moderate Risk",
    color: "var(--bg-warning-primary)",
    chartColor: "var(--bg-warning-primary)",
    minScore: 31,
    maxScore: 60,
  },
  SUCCESS: {
    label: "Secure",
    color: "var(--bg-pass-primary)",
    chartColor: "var(--bg-pass-primary)",
    minScore: 61,
    maxScore: 100,
  },
} as const;

type ThreatLevelKey = keyof typeof THREAT_LEVEL_CONFIG;

interface ThreatScoreProps {
  score?: number | null;
  scoreDelta?: number | null;
  sectionScores?: SectionScores;
  criticalRequirements?: CriticalRequirement[];
  onViewRemediationPlan?: () => void;
  className?: string;
}

function getThreatLevel(score: number): ThreatLevelKey {
  for (const [key, config] of Object.entries(THREAT_LEVEL_CONFIG)) {
    if (score >= config.minScore && score <= config.maxScore) {
      return key as ThreatLevelKey;
    }
  }
  return "WARNING";
}

// Convert section scores to tooltip data for the radial chart
function convertSectionScoresToTooltipData(
  sectionScores?: SectionScores,
): Array<{ name: string; value: number; color: string }> {
  if (!sectionScores) return [];

  return Object.entries(sectionScores).map(([name, value]) => {
    // Round to nearest integer
    const roundedValue = Math.round(value);

    // Determine color based on the same ranges as THREAT_LEVEL_CONFIG
    const threatLevel = getThreatLevel(roundedValue);
    const color = THREAT_LEVEL_CONFIG[threatLevel].chartColor;

    return { name, value: roundedValue, color };
  });
}

// Extract top gap names from critical requirements
function extractTopGaps(
  criticalRequirements?: CriticalRequirement[],
  limit = 2,
): string[] {
  if (!criticalRequirements || criticalRequirements.length === 0) return [];

  // Sort by risk_level descending, then by weight descending
  const sorted = [...criticalRequirements].sort((a, b) => {
    if (b.risk_level !== a.risk_level) {
      return b.risk_level - a.risk_level;
    }
    return b.weight - a.weight;
  });

  return sorted.slice(0, limit).map((req) => req.title);
}

export function ThreatScore({
  score,
  scoreDelta,
  sectionScores,
  criticalRequirements,
}: ThreatScoreProps) {
  const hasData = score !== null && score !== undefined;
  const displayScore = hasData ? score : 0;

  const threatLevel = getThreatLevel(displayScore);
  const config = THREAT_LEVEL_CONFIG[threatLevel];

  // Convert section scores to tooltip data
  const tooltipData = convertSectionScoresToTooltipData(sectionScores);

  // Extract top gaps from critical requirements
  const gaps = extractTopGaps(criticalRequirements, 2);

  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[328px] flex-col justify-between md:max-w-[312px]"
    >
      <CardHeader>
        <CardTitle>Prowler Threat Score</CardTitle>
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        {/* Radial Chart */}
        <div className="relative mx-auto h-[172px] w-full max-w-[250px]">
          <div className="absolute top-0 left-1/2 z-1 w-full -translate-x-1/2">
            <RadialChart
              percentage={displayScore}
              label="Score"
              color={config.chartColor}
              backgroundColor="var(--bg-neutral-tertiary)"
              height={206}
              innerRadius={90}
              outerRadius={115}
              startAngle={200}
              endAngle={-20}
              hasDots
              tooltipData={tooltipData}
            />
          </div>
          {/* Overlaid Text (centered) */}
          {hasData && (
            <div className="pointer-events-none absolute top-[65%] left-1/2 z-0 -translate-x-1/2 -translate-y-1/2 text-center">
              <p className="text-text-neutral-secondary text-sm text-nowrap">
                {config.label}
              </p>
            </div>
          )}
        </div>

        {/* Info Box or Empty State */}
        {hasData ? (
          <Card
            variant="inner"
            padding="md"
            className="items-center justify-center"
          >
            <div className="text-text-neutral-secondary flex flex-col gap-1.5 text-sm leading-6">
              {/* Improvement Message */}
              {scoreDelta !== undefined &&
                scoreDelta !== null &&
                scoreDelta !== 0 && (
                  <div className="flex items-center gap-1">
                    <ThumbsUp size={14} className="flex-shrink-0" />
                    <p>
                      Threat score has{" "}
                      {scoreDelta > 0 ? "improved" : "decreased"} by{" "}
                      {Math.abs(scoreDelta)}%
                    </p>
                  </div>
                )}

              {/* Gaps Message */}
              {gaps.length > 0 && (
                <div className="flex items-start gap-1">
                  <MessageCircleWarning
                    size={14}
                    className="mt-1 flex-shrink-0"
                  />
                  <p>
                    Major gaps include {gaps.slice(0, 2).join(", ")}
                    {gaps.length > 2 && ` & ${gaps.length - 2} more...`}
                  </p>
                </div>
              )}
            </div>
          </Card>
        ) : (
          <Card
            variant="inner"
            padding="md"
            className="items-center justify-center"
          >
            <p className="text-text-neutral-secondary text-sm">
              Threat Score Data Unavailable
            </p>
          </Card>
        )}
      </CardContent>
    </Card>
  );
}

export function ThreatScoreSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] min-w-[328px] flex-col justify-between md:max-w-[312px]"
    >
      <CardHeader>
        <Skeleton className="h-7 w-36 rounded-xl" />
      </CardHeader>

      <CardContent className="flex flex-1 flex-col justify-between space-y-4">
        {/* Circular skeleton for radial chart */}
        <div className="relative mx-auto h-[172px] w-full max-w-[250px]">
          <Skeleton className="mx-auto size-[170px] rounded-full" />
        </div>

        {/* Bottom info box skeleton */}
        <Skeleton className="h-[97px] w-full shrink-0 rounded-xl" />
      </CardContent>
    </Card>
  );
}
