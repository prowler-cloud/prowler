"use client";

import { Tooltip } from "@nextui-org/react";
import { DownloadIcon } from "lucide-react";

import { CustomButton } from "../custom/custom-button";

interface DownloadThreatscoreButtonProps {
  paramId: string;
  onDownload: (paramId: string) => void;
  ariaLabel?: string;
  isDisabled?: boolean;
  textTooltip?: string;
  isDownloading?: boolean;
}

export const DownloadThreatscoreButton = ({
  paramId,
  onDownload,
  ariaLabel = "Download ThreatScore report",
  isDisabled,
  textTooltip = "Download ThreatScore report",
  isDownloading = false,
}: DownloadThreatscoreButtonProps) => {
  return (
    <div className="flex items-center justify-end">
      <Tooltip content={textTooltip} className="text-xs">
        <CustomButton
          variant="solid"
          color="success"
          isDisabled={isDisabled || isDownloading}
          onPress={() => onDownload(paramId)}
          className="border-0 bg-gradient-to-r from-green-500 to-emerald-600 font-semibold text-white shadow-lg transition-all duration-200 hover:from-green-600 hover:to-emerald-700 hover:shadow-xl"
          ariaLabel={ariaLabel}
          size="md"
          startContent={
            isDownloading ? (
              <div className="h-4 w-4 animate-spin rounded-full border-b-2 border-white" />
            ) : (
              <DownloadIcon size={18} className="text-white" />
            )
          }
        >
          {isDownloading ? "Downloading..." : "Download ThreatScore Report"}
        </CustomButton>
      </Tooltip>
    </div>
  );
};
