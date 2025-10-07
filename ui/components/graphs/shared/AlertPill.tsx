import { AlertTriangle } from "lucide-react";

import { CHART_COLORS } from "./chart-constants";

interface AlertPillProps {
  value: number;
  label?: string;
  iconSize?: number;
  textSize?: "xs" | "sm" | "base";
}

export function AlertPill({
  value,
  label = "Fail Findings",
  iconSize = 12,
  textSize = "xs",
}: AlertPillProps) {
  const textSizeClass = `text-${textSize}`;

  return (
    <div className="flex items-center gap-2">
      <div
        className="flex items-center gap-1 rounded-full px-2 py-1"
        style={{ backgroundColor: CHART_COLORS.alertPillBg }}
      >
        <AlertTriangle
          size={iconSize}
          style={{ color: CHART_COLORS.alertPillText }}
        />
        <span
          className={`${textSizeClass} font-semibold`}
          style={{ color: CHART_COLORS.alertPillText }}
        >
          {value}
        </span>
      </div>
      <span
        className={textSizeClass}
        style={{ color: CHART_COLORS.textSecondary }}
      >
        {label}
      </span>
    </div>
  );
}
