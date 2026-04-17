"use client";

import Link from "next/link";
import { useState } from "react";

import { MutedIcon } from "@/components/icons";
import { Button } from "@/components/shadcn";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/shadcn/popover";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { DOCS_URLS } from "@/lib/external-urls";
import { cn } from "@/lib/utils";
import { FINDING_DELTA, type FindingDelta } from "@/types";

export const DeltaValues = FINDING_DELTA;

export type DeltaType = Exclude<FindingDelta, null>;

interface NotificationIndicatorProps {
  delta?: DeltaType;
  isMuted?: boolean;
  mutedReason?: string;
  showDeltaWhenMuted?: boolean;
}

export const NotificationIndicator = ({
  delta,
  isMuted = false,
  mutedReason,
  showDeltaWhenMuted = false,
}: NotificationIndicatorProps) => {
  const hasDelta = delta === DeltaValues.NEW || delta === DeltaValues.CHANGED;

  if (isMuted && hasDelta && showDeltaWhenMuted) {
    return (
      <div className="flex shrink-0 items-center gap-1">
        <MutedIndicator mutedReason={mutedReason} />
        <DeltaIndicator delta={delta} />
      </div>
    );
  }

  // Uses Popover (not Tooltip) because the content has an interactive link.
  // Radix Tooltip does not support interactive content — clicks fall through.
  if (isMuted) {
    return <MutedIndicator mutedReason={mutedReason} />;
  }

  // Show dot with tooltip for new or changed findings
  if (hasDelta) {
    return <DeltaIndicator delta={delta} />;
  }

  // No indicator - return minimal width placeholder
  return <div className="w-2 shrink-0" />;
};

function DeltaIndicator({
  delta,
}: {
  delta: typeof DeltaValues.NEW | typeof DeltaValues.CHANGED;
}) {
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

/** Muted indicator with hover-triggered Popover for interactive link. */
function MutedIndicator({ mutedReason }: { mutedReason?: string }) {
  const [open, setOpen] = useState(false);

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          type="button"
          className="flex w-5 shrink-0 cursor-pointer items-center justify-center bg-transparent p-0"
          onClick={(e) => e.stopPropagation()}
          onMouseEnter={() => setOpen(true)}
          onMouseLeave={() => setOpen(false)}
        >
          <MutedIcon className="text-bg-data-muted size-3" />
        </button>
      </PopoverTrigger>
      <PopoverContent
        className="border-border-neutral-tertiary bg-bg-neutral-tertiary w-auto rounded-lg px-2 py-1.5 shadow-lg"
        sideOffset={4}
        onMouseEnter={() => setOpen(true)}
        onMouseLeave={() => setOpen(false)}
        onClick={(e) => e.stopPropagation()}
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
      </PopoverContent>
    </Popover>
  );
}
