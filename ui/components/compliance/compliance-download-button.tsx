"use client";

import { Button } from "@heroui/button";
import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { toast } from "@/components/ui";
import {
  COMPLIANCE_REPORT_BUTTON_LABELS,
  type ComplianceReportType,
} from "@/lib/compliance/compliance-report-types";
import { downloadComplianceReportPdf } from "@/lib/helper";

interface ComplianceDownloadButtonProps {
  scanId: string;
  reportType: ComplianceReportType;
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

  const defaultLabel = COMPLIANCE_REPORT_BUTTON_LABELS[reportType];

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
