"use client";

import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
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
      variant="default"
      size="sm"
      onClick={handleDownload}
      disabled={isDownloading}
    >
      <DownloadIcon
        className={isDownloading ? "animate-download-icon" : ""}
        size={16}
      />
      PDF ThreatScore Report
    </Button>
  );
};
