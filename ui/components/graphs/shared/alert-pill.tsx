import { AlertTriangle } from "lucide-react";

import { cn } from "@/lib";

import { CHART_COLORS } from "./constants";

interface AlertPillProps {
  value: number;
  label?: string;
  iconSize?: number;
  textSize?: "xs" | "sm" | "base";
}

const TEXT_SIZE_CLASSES = {
  sm: "text-sm",
  base: "text-base",
  xs: "text-xs",
} as const;

export function AlertPill({
  value,
  label = "Fail Findings",
  iconSize = 12,
  textSize = "xs",
}: AlertPillProps) {
  const textSizeClass = TEXT_SIZE_CLASSES[textSize];

  // Chart alert colors are theme-aware variables from globals.css
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
          className={cn(textSizeClass, "font-semibold")}
          style={{ color: CHART_COLORS.alertPillText }}
        >
          {value}
        </span>
      </div>
      <span className="text-text-neutral-secondary text-sm font-medium">
        {label}
      </span>
    </div>
  );
}
