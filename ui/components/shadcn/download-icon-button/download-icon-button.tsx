"use client";

import { DownloadIcon } from "lucide-react";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";

interface DownloadIconButtonProps {
  paramId: string;
  onDownload: (paramId: string) => void;
  ariaLabel?: string;
  isDisabled?: boolean;
  textTooltip?: string;
  isDownloading?: boolean;
}

export const DownloadIconButton = ({
  paramId,
  onDownload,
  ariaLabel = "Download report",
  isDisabled,
  textTooltip = "Download report",
  isDownloading = false,
}: DownloadIconButtonProps) => {
  return (
    <div className="flex items-center justify-end">
      <Tooltip>
        <TooltipTrigger asChild>
          <Button
            variant="ghost"
            size="icon-sm"
            disabled={isDisabled || isDownloading}
            onClick={() => onDownload(paramId)}
            aria-label={ariaLabel}
            className="p-0 disabled:opacity-30"
          >
            <DownloadIcon
              className={isDownloading ? "animate-download-icon" : ""}
              size={16}
            />
          </Button>
        </TooltipTrigger>
        <TooltipContent className="text-xs">{textTooltip}</TooltipContent>
      </Tooltip>
    </div>
  );
};
