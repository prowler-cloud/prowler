import Link from "next/link";

import { MutedIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { DOCS_URLS } from "@/lib/external-urls";
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
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            className="flex w-2 shrink-0 cursor-pointer items-center justify-center"
            onClick={(e) => e.stopPropagation()}
          >
            <MutedIcon className="text-bg-data-muted size-2" />
          </div>
        </TooltipTrigger>
        <TooltipContent
          onClick={(e) => e.stopPropagation()}
          onPointerDownCapture={(e) => e.stopPropagation()}
        >
          <Link
            href="/mutelist"
            onClick={(e) => e.stopPropagation()}
            className="text-button-tertiary hover:text-button-tertiary-hover flex items-center gap-1 text-xs underline-offset-4"
          >
            {mutedReason ? (
              <>
                <span className="text-text-neutral-primary">Mute rule:</span>
                <span className="max-w-[150px] truncate">{mutedReason}</span>
              </>
            ) : (
              <>
                <span className="text-text-neutral-primary">Mute rule:</span>
                <span>view rules</span>
              </>
            )}
          </Link>
        </TooltipContent>
      </Tooltip>
    );
  }

  // Show dot with tooltip for new or changed findings
  if (delta === DeltaValues.NEW || delta === DeltaValues.CHANGED) {
    return (
      <Tooltip>
        <TooltipTrigger asChild>
          <div
            onClick={(e) => e.stopPropagation()}
            className="flex w-2 shrink-0 cursor-pointer items-center justify-center"
          >
            <div
              className={cn(
                "size-1.5 rounded-full",
                delta === DeltaValues.NEW
                  ? "bg-system-severity-high"
                  : "bg-system-severity-low",
              )}
            />
          </div>
        </TooltipTrigger>
        <TooltipContent>
          <div className="flex items-center gap-1 text-xs">
            <span>
              {delta === DeltaValues.NEW
                ? "New finding."
                : "Status changed since the previous scan."}
            </span>
            <Button
              aria-label="Learn more about findings"
              variant="link"
              size="default"
              className="text-button-primary h-auto min-w-0 p-0 text-xs"
              asChild
            >
              <a
                href={DOCS_URLS.FINDINGS_ANALYSIS}
                target="_blank"
                rel="noopener noreferrer"
              >
                Learn more
              </a>
            </Button>
          </div>
        </TooltipContent>
      </Tooltip>
    );
  }

  // No indicator - return minimal width placeholder
  return <div className="w-2 shrink-0" />;
};
