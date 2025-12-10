import { AlertTriangle } from "lucide-react";

import { cn } from "@/lib";

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
        style={{ backgroundColor: "var(--color-bg-fail-secondary)" }}
      >
        <AlertTriangle
          size={iconSize}
          style={{ color: "var(--color-text-error-primary)" }}
        />
        <span
          className={cn(textSizeClass, "font-semibold")}
          style={{ color: "var(--color-text-error-primary)" }}
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
