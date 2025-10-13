import { AlertTriangle } from "lucide-react";

import { cn } from "@/lib/utils";

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
  return (
    <div className="flex items-center gap-2">
      <div className="bg-alert-pill-bg flex items-center gap-1 rounded-full px-2 py-1">
        <AlertTriangle size={iconSize} className="text-alert-pill-text" />
        <span
          className={cn(
            `text-${textSize}`,
            "text-alert-pill-text font-semibold",
          )}
        >
          {value}
        </span>
      </div>
      <span className={cn(`text-${textSize}`, "text-slate-400")}>{label}</span>
    </div>
  );
}
