"use client";

import { useState } from "react";

import { useToast } from "@/components/ui";
import { downloadThreatscoreReport } from "@/lib/helper";

import { DownloadThreatscoreButton } from "./download-threatscore-button";

interface ThreatscoreDownloadButtonProps {
  scanId: string;
  isDisabled?: boolean;
}

export const ThreatscoreDownloadButton = ({
  scanId,
  isDisabled = false,
}: ThreatscoreDownloadButtonProps) => {
  const { toast } = useToast();
  const [isDownloading, setIsDownloading] = useState(false);

  const handleDownload = async () => {
    setIsDownloading(true);
    try {
      await downloadThreatscoreReport(scanId, toast);
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <DownloadThreatscoreButton
      paramId={scanId}
      onDownload={handleDownload}
      isDisabled={isDisabled || isDownloading}
      isDownloading={isDownloading}
    />
  );
};
