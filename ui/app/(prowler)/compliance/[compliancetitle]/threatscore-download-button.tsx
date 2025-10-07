"use client";

import { Button } from "@heroui/button";
import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { toast } from "@/components/ui";
import { downloadThreatScorePdf } from "@/lib/helper";

interface ThreatScoreDownloadButtonProps {
  scanId: string;
}

export const ThreatScoreDownloadButton = ({
  scanId,
}: ThreatScoreDownloadButtonProps) => {
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  const handleDownload = async () => {
    setIsDownloading(true);
    try {
      await downloadThreatScorePdf(scanId, toast);
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <Button
      color="success"
      variant="solid"
      startContent={
        <DownloadIcon
          className={isDownloading ? "animate-download-icon" : ""}
          size={16}
        />
      }
      onPress={handleDownload}
      isLoading={isDownloading}
      size="sm"
    >
      ThreatScore Report
    </Button>
  );
};
