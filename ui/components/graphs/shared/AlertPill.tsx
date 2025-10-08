import { AlertTriangle } from "lucide-react";

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
      <div className="flex items-center gap-1 rounded-full bg-alert-pill-bg px-2 py-1">
        <AlertTriangle size={iconSize} className="text-alert-pill-text" />
        <span className={`${textSizeClass} font-semibold text-alert-pill-text`}>
          {value}
        </span>
      </div>
      <span className={`${textSizeClass} text-slate-400`}>
        {label}
      </span>
    </div>
  );
}
