"use client";

import { Tooltip } from "@nextui-org/react";
import { DownloadIcon } from "lucide-react";

import { CustomButton } from "../custom/custom-button";

interface DownloadIconButtonProps {
  paramId: string;
  onDownload: (paramId: string) => void;
  ariaLabel?: string;
  isDisabled?: boolean;
  textTooltip?: string;
}

export const DownloadIconButton = ({
  paramId,
  onDownload,
  ariaLabel = "Download report",
  isDisabled = false,
  textTooltip = "Download report",
}: DownloadIconButtonProps) => {
  return (
    <div className="flex items-center justify-end">
      <Tooltip content={textTooltip} className="text-xs">
        <CustomButton
          variant="ghost"
          isDisabled={isDisabled}
          onPress={() => onDownload(paramId)}
          className="p-0 text-default-500 hover:text-primary disabled:opacity-30"
          isIconOnly
          ariaLabel={ariaLabel}
          size="sm"
        >
          <DownloadIcon size={16} />
        </CustomButton>
      </Tooltip>
    </div>
  );
};
