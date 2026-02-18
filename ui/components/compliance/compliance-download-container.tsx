"use client";

import { DownloadIcon, FileTextIcon } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import { toast } from "@/components/ui";
import type { ComplianceReportType } from "@/lib/compliance/compliance-report-types";
import {
  downloadComplianceCsv,
  downloadComplianceReportPdf,
} from "@/lib/helper";
import { cn } from "@/lib/utils";

interface ComplianceDownloadContainerProps {
  scanId: string;
  complianceId: string;
  reportType?: ComplianceReportType;
  compact?: boolean;
  disabled?: boolean;
}

export const ComplianceDownloadContainer = ({
  scanId,
  complianceId,
  reportType,
  compact = false,
  disabled = false,
}: ComplianceDownloadContainerProps) => {
  const [isDownloadingCsv, setIsDownloadingCsv] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

  const handleDownloadCsv = async () => {
    if (isDownloadingCsv) return;
    setIsDownloadingCsv(true);
    try {
      await downloadComplianceCsv(scanId, complianceId, toast);
    } finally {
      setIsDownloadingCsv(false);
    }
  };

  const handleDownloadPdf = async () => {
    if (!reportType || isDownloadingPdf) return;
    setIsDownloadingPdf(true);
    try {
      await downloadComplianceReportPdf(scanId, reportType, toast);
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const buttonClassName = cn(
    "border-button-primary text-button-primary hover:bg-button-primary/10",
    compact && "h-7 px-2 text-xs",
  );

  return (
    <div className={cn("flex gap-2", compact ? "items-center" : "flex-col")}>
      <Button
        size="sm"
        variant="outline"
        className={buttonClassName}
        onClick={handleDownloadCsv}
        disabled={disabled || isDownloadingCsv}
        aria-label="Download compliance CSV report"
      >
        <FileTextIcon
          size={14}
          className={isDownloadingCsv ? "animate-download-icon" : ""}
        />
        CSV
      </Button>
      {reportType && (
        <Button
          size="sm"
          variant="outline"
          className={buttonClassName}
          onClick={handleDownloadPdf}
          disabled={disabled || isDownloadingPdf}
          aria-label="Download compliance PDF report"
        >
          <DownloadIcon
            size={14}
            className={isDownloadingPdf ? "animate-download-icon" : ""}
          />
          PDF
        </Button>
      )}
    </div>
  );
};
