"use client";

import { Button } from "@heroui/button";
import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { toast } from "@/components/ui";
import { downloadComplianceReportPdf } from "@/lib/helper";

interface ComplianceDownloadButtonProps {
  scanId: string;
  reportType: "threatscore" | "ens";
  label?: string;
}

export const ComplianceDownloadButton = ({
  scanId,
  reportType,
  label,
}: ComplianceDownloadButtonProps) => {
  const [isDownloading, setIsDownloading] = useState<boolean>(false);

  const handleDownload = async () => {
    setIsDownloading(true);
    try {
      await downloadComplianceReportPdf(scanId, reportType, toast);
    } finally {
      setIsDownloading(false);
    }
  };

  const defaultLabel = reportType === "threatscore" ? "PDF ThreatScore Report" : "PDF ENS Report";

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
      {label || defaultLabel}
    </Button>
  );
};
