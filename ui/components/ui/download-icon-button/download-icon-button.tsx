"use client";

import { downloadScanZip } from "@/lib/helper";
import { CustomButton } from "../custom/custom-button";
import { toast } from "@/components/ui";
import { DownloadIcon } from "lucide-react";

interface DownloadIconButtonProps {
  paramId: string;
  ariaLabel?: string;
  isDisabled?: boolean;
}

export const DownloadIconButton = ({
  paramId,
  ariaLabel = "Download report",
  isDisabled = false,
}: DownloadIconButtonProps) => {
  return (
    <div className="flex w-14 items-center justify-center">
      <CustomButton
        variant="ghost"
        isDisabled={isDisabled}
        onPress={() => downloadScanZip(paramId, toast)}
        className="p-0 text-default-500 hover:text-primary disabled:opacity-30"
        isIconOnly
        ariaLabel={ariaLabel}
        size="sm"
      >
        <DownloadIcon size={16} />
      </CustomButton>
    </div>
  );
};
