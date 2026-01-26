"use client";

import { DownloadIcon } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
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
  /** Show only icon with tooltip on mobile (sm and below) */
  iconOnlyOnMobile?: boolean;
}

export const ComplianceDownloadButton = ({
  scanId,
  reportType,
  label,
  iconOnlyOnMobile = false,
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
  const buttonLabel = label || defaultLabel;

  if (iconOnlyOnMobile) {
    return (
      <>
        {/* Mobile and Tablet: Icon only with tooltip */}
        <Tooltip>
          <TooltipTrigger asChild>
            <Button
              variant="default"
              size="icon"
              onClick={handleDownload}
              disabled={isDownloading}
              className="md:hidden"
              aria-label={buttonLabel}
            >
              <DownloadIcon
                className={isDownloading ? "animate-download-icon" : ""}
                size={16}
              />
            </Button>
          </TooltipTrigger>
          <TooltipContent>{buttonLabel}</TooltipContent>
        </Tooltip>
        {/* Desktop: Full button with label */}
        <Button
          variant="default"
          size="sm"
          onClick={handleDownload}
          disabled={isDownloading}
          className="hidden md:inline-flex"
        >
          <DownloadIcon
            className={isDownloading ? "animate-download-icon" : ""}
            size={16}
          />
          {buttonLabel}
        </Button>
      </>
    );
  }

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
      {buttonLabel}
    </Button>
  );
};
