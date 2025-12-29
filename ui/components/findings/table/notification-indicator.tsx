import Link from "next/link";

import { MutedIcon } from "@/components/icons";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { cn } from "@/lib/utils";

export const DeltaValues = {
  NEW: "new",
  CHANGED: "changed",
  NONE: "none",
} as const;

export type DeltaType = (typeof DeltaValues)[keyof typeof DeltaValues];

interface NotificationIndicatorProps {
  delta?: DeltaType;
  isMuted?: boolean;
  mutedReason?: string;
}

export const NotificationIndicator = ({
  delta,
  isMuted = false,
  mutedReason,
}: NotificationIndicatorProps) => {
  // Muted takes precedence over delta
  if (isMuted) {
    const ruleName = mutedReason || "Unknown rule";

    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div className="ml-1 flex cursor-pointer items-center justify-center">
            <MutedIcon className="text-bg-data-muted size-2" />
          </div>
        </TooltipTrigger>
        <TooltipContent>
          <Link
            href="/mutelist"
            className="text-button-tertiary hover:text-button-tertiary-hover flex items-center gap-1 text-xs underline-offset-4"
          >
            <span className="text-text-neutral-primary">Mute rule:</span>
            <span className="max-w-[150px] truncate">{ruleName}</span>
          </Link>
        </TooltipContent>
      </Tooltip>
    );
  }

  // Show pink dot for new or changed findings
  if (delta === DeltaValues.NEW || delta === DeltaValues.CHANGED) {
    return (
      <div
        className={cn("ml-1 size-1.5 rounded-full", "bg-bg-data-critical")}
      />
    );
  }

  // No indicator - return minimal width placeholder
  return <div className="w-2" />;
};
