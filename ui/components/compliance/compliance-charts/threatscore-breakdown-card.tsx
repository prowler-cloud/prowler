"use client";

import { Progress } from "@heroui/progress";

import type { SectionScores } from "@/actions/overview/threat-score";
import { RadialChart } from "@/components/graphs/radial-chart";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";
import {
  getScoreColor,
  getScoreLabel,
  getScoreLevel,
  getScoreTextClass,
  SCORE_COLORS,
} from "@/lib/compliance/score-utils";

export interface ThreatScoreBreakdownCardProps {
  overallScore: number;
  sectionScores: SectionScores;
}

export function ThreatScoreBreakdownCard({
  overallScore,
  sectionScores,
}: ThreatScoreBreakdownCardProps) {
  const scoreLevel = getScoreLevel(overallScore);
  const scoreColor = SCORE_COLORS[scoreLevel];

  // Convert section scores to tooltip data for the radial chart
  const tooltipData = Object.entries(sectionScores).map(([name, value]) => ({
    name,
    value,
    color: SCORE_COLORS[getScoreLevel(value)],
  }));

  // Sort sections by score (lowest first to highlight areas needing attention)
  const sortedSections = Object.entries(sectionScores).sort(
    ([, a], [, b]) => a - b,
  );

  return (
    <Card variant="base" className="flex h-full w-full flex-col">
      <CardHeader>
        <CardTitle>ThreatScore Breakdown</CardTitle>
      </CardHeader>
      {/* Mobile: vertical, Tablet: horizontal, Desktop: vertical */}
      <CardContent className="flex flex-1 flex-col gap-4 md:flex-row md:items-stretch lg:flex-col">
        {/* Overall Score - Large radial chart matching overview style */}
        <div className="flex w-full flex-col items-center justify-center md:w-[160px] md:flex-shrink-0 lg:w-full">
          <div className="relative mx-auto h-[140px] w-[160px]">
            <div className="absolute top-0 left-1/2 z-1 w-full -translate-x-1/2">
              <RadialChart
                percentage={overallScore}
                label="Score"
                color={scoreColor}
                backgroundColor={SCORE_COLORS.NEUTRAL}
                height={170}
                innerRadius={70}
                outerRadius={90}
                startAngle={200}
                endAngle={-20}
                tooltipData={tooltipData}
              />
            </div>
            {/* Overlaid label below percentage */}
            <div className="text-text-neutral-secondary pointer-events-none absolute top-[65%] left-1/2 z-0 -translate-x-1/2 -translate-y-1/2 text-center text-sm text-nowrap">
              {getScoreLabel(overallScore)}
            </div>
          </div>
        </div>

        {/* Pillar Breakdown */}
        <Card variant="inner" padding="sm" className="min-w-0 flex-1">
          <div className="mb-2">
            <span className="text-default-600 text-xs font-medium tracking-wide uppercase">
              Score by Pillar
            </span>
          </div>
          <div className="space-y-2">
            {sortedSections.map(([section, score]) => (
              <div key={section} className="space-y-0.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-default-700 truncate pr-2">
                    {section}
                  </span>
                  <span className={`font-semibold ${getScoreTextClass(score)}`}>
                    {score.toFixed(1)}%
                  </span>
                </div>
                <Progress
                  aria-label={`${section} score`}
                  value={score}
                  color={getScoreColor(score)}
                  size="md"
                  className="w-full"
                />
              </div>
            ))}
          </div>
        </Card>
      </CardContent>
    </Card>
  );
}

const SKELETON_PILLAR_COUNT = 5;

export function ThreatScoreBreakdownCardSkeleton() {
  return (
    <Card variant="base" className="flex h-full w-full animate-pulse flex-col">
      <CardHeader>
        <div className="bg-default-200 h-5 w-40 rounded" />
      </CardHeader>
      {/* Mobile: vertical, Tablet: horizontal, Desktop: vertical */}
      <CardContent className="flex flex-1 flex-col gap-4 md:flex-row md:items-stretch lg:flex-col">
        <div className="flex w-full flex-col items-center justify-center md:w-[160px] md:flex-shrink-0 lg:w-full">
          <div className="bg-default-200 mx-auto h-[140px] w-[140px] rounded-full" />
        </div>
        <Card variant="inner" padding="sm" className="min-w-0 flex-1">
          <div className="space-y-2">
            {Array.from({ length: SKELETON_PILLAR_COUNT }, (_, i) => (
              <div key={i} className="space-y-0.5">
                <div className="flex justify-between">
                  <div className="bg-default-200 h-3 w-28 rounded" />
                  <div className="bg-default-200 h-3 w-10 rounded" />
                </div>
                <div className="bg-default-200 h-2 w-full rounded" />
              </div>
            ))}
          </div>
        </Card>
      </CardContent>
    </Card>
  );
}
