"use client";

import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
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
      variant="default"
      size="sm"
      onClick={handleDownload}
      disabled={isDownloading}
    >
      <DownloadIcon
        className={isDownloading ? "animate-download-icon" : ""}
        size={16}
      />
      {label || defaultLabel}
    </Button>
  );
};
