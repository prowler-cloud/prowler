"use client";

import { Tooltip } from "@heroui/tooltip";
import { DownloadIcon } from "lucide-react";

import { CustomButton } from "../custom/custom-button";

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
      <Tooltip content={textTooltip} className="text-xs">
        <CustomButton
          variant="ghost"
          isDisabled={isDisabled || isDownloading}
          onPress={() => onDownload(paramId)}
          className="text-default-500 hover:text-primary p-0 disabled:opacity-30"
          isIconOnly
          ariaLabel={ariaLabel}
          size="sm"
        >
          <DownloadIcon
            className={isDownloading ? "animate-download-icon" : ""}
            size={16}
          />
        </CustomButton>
      </Tooltip>
    </div>
  );
};
