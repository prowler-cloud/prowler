"use client";

import { MessageCircleWarning, ThumbsUp } from "lucide-react";

import { RadialChart } from "@/components/graphs/radial-chart";
import {
  SEVERITY_COLORS,
  STATUS_COLORS,
} from "@/components/graphs/shared/constants";
import {
  BaseCard,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/shadcn";

const THREAT_LEVEL_CONFIG = {
  CRITICAL: {
    label: "Critical Risk",
    color: "text-red-500",
    chartColor: SEVERITY_COLORS.Critical,
    minScore: 0,
    maxScore: 20,
  },
  HIGH: {
    label: "High Risk",
    color: "text-orange-500",
    chartColor: SEVERITY_COLORS.High,
    minScore: 21,
    maxScore: 40,
  },
  MODERATE: {
    label: "Moderately Secure",
    color: "text-yellow-500",
    chartColor: SEVERITY_COLORS.Medium,
    minScore: 41,
    maxScore: 60,
  },
  LOW: {
    label: "Low Risk",
    color: "text-blue-500",
    chartColor: SEVERITY_COLORS.Low,
    minScore: 61,
    maxScore: 80,
  },
  SECURE: {
    label: "Highly Secure",
    color: "text-green-500",
    chartColor: STATUS_COLORS.Success,
    minScore: 81,
    maxScore: 100,
  },
} as const;

type ThreatLevelKey = keyof typeof THREAT_LEVEL_CONFIG;

interface ThreatScoreProps {
  score: number;
  improvement?: number;
  gaps?: string[];
  onViewRemediationPlan?: () => void;
  className?: string;
}

function getThreatLevel(score: number): ThreatLevelKey {
  for (const [key, config] of Object.entries(THREAT_LEVEL_CONFIG)) {
    if (score >= config.minScore && score <= config.maxScore) {
      return key as ThreatLevelKey;
    }
  }
  return "MODERATE";
}

export function ThreatScore({
  score,
  improvement,
  gaps = [],
}: ThreatScoreProps) {
  const threatLevel = getThreatLevel(score);
  const config = THREAT_LEVEL_CONFIG[threatLevel];

  return (
    <BaseCard className="flex min-h-[372px] min-w-[312px] flex-col justify-between md:max-w-[312px]">
      <CardHeader>
        <CardTitle>Prowler Threat Score</CardTitle>
      </CardHeader>

      <CardContent className="space-y-2">
        {/* Radial Chart */}
        <div className="relative mx-auto h-[150px] w-full max-w-[250px]">
          <div className="absolute top-0 left-1/2 h-full w-full -translate-x-1/2">
            <RadialChart
              percentage={score}
              label="Score"
              color={config.chartColor}
              backgroundColor="rgba(100, 100, 100, 0.2)"
              height={206}
              innerRadius={90}
              outerRadius={115}
              startAngle={200}
              endAngle={-20}
              hasDots
            />
          </div>
          {/* Overlaid Text (centered) */}
          <div className="absolute top-[75%] left-1/2 -translate-x-1/2 -translate-y-1/2 text-center">
            <p className="text-sm text-nowrap text-slate-900 dark:text-zinc-300">
              {config.label}
            </p>
          </div>
        </div>

        {/* Info Box */}
        <div className="flex-1 rounded-xl border border-slate-300 bg-[#F8FAFC80] px-3 py-[9px] backdrop-blur-[46px] dark:border-[rgba(38,38,38,0.70)] dark:bg-[rgba(23,23,23,0.50)]">
          <div className="flex flex-col gap-1.5 text-sm leading-6 text-zinc-800 dark:text-zinc-300">
            {/* Improvement Message */}
            {improvement !== undefined && improvement !== 0 && (
              <div className="flex items-center gap-1">
                <ThumbsUp size={14} className="flex-shrink-0" />
                <p>
                  Threat score has {improvement > 0 ? "improved" : "decreased"}{" "}
                  by {Math.abs(improvement)}%.
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
                  {gaps.length > 2 && ` & ${gaps.length - 2} more...`}.
                </p>
              </div>
            )}

            {/* View Remediation Plan Button */}
            <button onClick={() => {}}>
              <span className="text-sm font-medium text-blue-600 dark:text-blue-300">
                View Remediation Plan
              </span>
            </button>
          </div>
        </div>
      </CardContent>
    </BaseCard>
  );
}
