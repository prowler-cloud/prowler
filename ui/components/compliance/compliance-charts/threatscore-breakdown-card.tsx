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
import { cn } from "@/lib/utils";

interface ThreatScoreBreakdownCardProps {
  overallScore: number;
  sectionScores: SectionScores;
  /** Makes the card full width with horizontal layout for mobile/tablet */
  fullWidth?: boolean;
}

export function ThreatScoreBreakdownCard({
  overallScore,
  sectionScores,
  fullWidth = false,
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
    <Card
      variant="base"
      className={cn(
        "flex flex-col justify-between",
        fullWidth
          ? "w-full"
          : "min-h-[372px] w-full md:w-auto md:max-w-[320px] md:min-w-[280px]",
      )}
    >
      <CardHeader>
        <CardTitle>ThreatScore Breakdown</CardTitle>
      </CardHeader>
      <CardContent
        className={cn(
          "flex gap-3",
          fullWidth ? "flex-row items-stretch" : "flex-1 flex-col",
        )}
      >
        {/* Overall Score - Compact */}
        <div
          className={cn(
            "flex gap-4",
            fullWidth
              ? "flex-col items-center justify-center"
              : "flex-row items-center",
          )}
        >
          <div className="relative h-[100px] w-[100px] flex-shrink-0">
            <RadialChart
              percentage={overallScore}
              label="Score"
              color={scoreColor}
              backgroundColor={SCORE_COLORS.NEUTRAL}
              height={100}
              innerRadius={35}
              outerRadius={45}
              startAngle={200}
              endAngle={-20}
              tooltipData={tooltipData}
              showCenterLabel={false}
            />
          </div>
          <div
            className={cn(
              "flex flex-col",
              fullWidth ? "items-center text-center" : "",
            )}
          >
            <span className="text-default-500 text-xs">Overall Score</span>
            <span
              className={`text-2xl font-bold ${getScoreTextClass(overallScore)}`}
            >
              {overallScore.toFixed(1)}%
            </span>
            <span className="text-default-400 text-xs">
              {getScoreLabel(overallScore)}
            </span>
          </div>
        </div>

        {/* Pillar Breakdown */}
        <Card variant="inner" padding="sm" className="flex-1">
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

interface ThreatScoreBreakdownCardSkeletonProps {
  fullWidth?: boolean;
}

export function ThreatScoreBreakdownCardSkeleton({
  fullWidth = false,
}: ThreatScoreBreakdownCardSkeletonProps = {}) {
  return (
    <Card
      variant="base"
      className={cn(
        "flex animate-pulse flex-col justify-between",
        fullWidth
          ? "w-full"
          : "min-h-[372px] w-full md:w-auto md:max-w-[320px] md:min-w-[280px]",
      )}
    >
      <CardHeader>
        <div className="bg-default-200 h-5 w-40 rounded" />
      </CardHeader>
      <CardContent
        className={cn(
          "flex gap-3",
          fullWidth ? "flex-row items-stretch" : "flex-1 flex-col",
        )}
      >
        <div
          className={cn(
            "flex gap-4",
            fullWidth
              ? "flex-col items-center justify-center"
              : "flex-row items-center",
          )}
        >
          <div className="bg-default-200 h-[100px] w-[100px] rounded-full" />
          <div
            className={cn(
              "flex flex-col gap-1",
              fullWidth ? "items-center" : "",
            )}
          >
            <div className="bg-default-200 h-3 w-16 rounded" />
            <div className="bg-default-200 h-6 w-20 rounded" />
            <div className="bg-default-200 h-3 w-14 rounded" />
          </div>
        </div>
        <Card variant="inner" padding="sm" className="flex-1">
          <div className="space-y-2">
            {[1, 2, 3, 4].map((i) => (
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
