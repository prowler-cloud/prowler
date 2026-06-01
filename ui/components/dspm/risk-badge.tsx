import { cn } from "@/lib/utils";

const RISK_BAND_STYLES = {
  low: "bg-bg-data-low",
  medium: "bg-bg-data-medium",
  high: "bg-bg-data-high",
  critical: "bg-bg-data-critical",
} as const;

type RiskBand = keyof typeof RISK_BAND_STYLES;

const getRiskBand = (score: number): RiskBand => {
  if (score >= 8) return "critical";
  if (score >= 5) return "high";
  if (score >= 3) return "medium";
  return "low";
};

interface RiskBadgeProps {
  score: number;
}

export const RiskBadge = ({ score }: RiskBadgeProps) => {
  const chipColor = RISK_BAND_STYLES[getRiskBand(score)];

  return (
    <div className="flex items-center gap-1">
      <div className={cn("size-3 rounded", chipColor)} />
      <span className="text-text-neutral-primary text-sm tabular-nums">
        {score}/10
      </span>
    </div>
  );
};
