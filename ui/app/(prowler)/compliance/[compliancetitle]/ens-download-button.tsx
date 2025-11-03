"use client";

import { Button } from "@heroui/button";
import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { toast } from "@/components/ui";
import { downloadEnsPdf } from "@/lib/helper";

interface EnsDownloadButtonProps {
  scanId: string;
}

export const EnsDownloadButton = ({ scanId }: EnsDownloadButtonProps) => {
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  const handleDownload = async () => {
    setIsDownloading(true);
    try {
      await downloadEnsPdf(scanId, toast);
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
      PDF ENS Report
    </Button>
  );
};
