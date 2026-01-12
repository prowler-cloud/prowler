"use client";

import { Progress } from "@heroui/progress";

import type { SectionScores } from "@/actions/overview/threat-score";
import { RadialChart } from "@/components/graphs/radial-chart";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/shadcn";

interface ThreatScoreBreakdownCardProps {
  overallScore: number;
  sectionScores: SectionScores;
}

const SCORE_COLORS = {
  DANGER: "var(--bg-fail-primary)",
  WARNING: "var(--bg-warning-primary)",
  SUCCESS: "var(--bg-pass-primary)",
  NEUTRAL: "var(--bg-neutral-tertiary)",
} as const;

function getScoreLevel(score: number): "SUCCESS" | "WARNING" | "DANGER" {
  if (score >= 80) return "SUCCESS";
  if (score >= 40) return "WARNING";
  return "DANGER";
}

function getScoreColor(score: number): "success" | "warning" | "danger" {
  if (score >= 80) return "success";
  if (score >= 40) return "warning";
  return "danger";
}

function getScoreLabel(score: number): string {
  if (score >= 80) return "Secure";
  if (score >= 40) return "Moderate Risk";
  return "Critical Risk";
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
    <Card
      variant="base"
      className="flex min-h-[372px] w-full flex-col justify-between md:w-auto md:max-w-[320px] md:min-w-[280px]"
    >
      <CardHeader>
        <CardTitle>ThreatScore Breakdown</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        {/* Overall Score - Compact */}
        <div className="flex items-center gap-4">
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
          <div className="flex flex-col">
            <span className="text-default-500 text-xs">Overall Score</span>
            <span
              className={`text-2xl font-bold ${
                overallScore >= 80
                  ? "text-success"
                  : overallScore >= 40
                    ? "text-warning"
                    : "text-danger"
              }`}
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
                  <span
                    className={`font-semibold ${
                      score >= 80
                        ? "text-success"
                        : score >= 40
                          ? "text-warning"
                          : "text-danger"
                    }`}
                  >
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

export function ThreatScoreBreakdownCardSkeleton() {
  return (
    <Card
      variant="base"
      className="flex min-h-[372px] w-full animate-pulse flex-col justify-between md:w-auto md:max-w-[320px] md:min-w-[280px]"
    >
      <CardHeader>
        <div className="bg-default-200 h-5 w-40 rounded" />
      </CardHeader>
      <CardContent className="flex flex-1 flex-col gap-3">
        <div className="flex items-center gap-4">
          <div className="bg-default-200 h-[100px] w-[100px] rounded-full" />
          <div className="flex flex-col gap-1">
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
