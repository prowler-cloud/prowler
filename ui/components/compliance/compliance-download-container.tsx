"use client";

import { DownloadIcon, FileTextIcon } from "lucide-react";
import { useState } from "react";

import { Button } from "@/components/shadcn/button/button";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/shadcn/tooltip";
import { toast } from "@/components/ui";
import type { ComplianceReportType } from "@/lib/compliance/compliance-report-types";
import { downloadComplianceCsv, downloadCompliancePdf } from "@/lib/helper";
import { cn } from "@/lib/utils";

interface ComplianceDownloadContainerProps {
  scanId: string;
  complianceId: string;
  reportType?: ComplianceReportType;
  compact?: boolean;
  disabled?: boolean;
  orientation?: "row" | "column";
  buttonWidth?: "auto" | "icon";
  presentation?: "buttons" | "dropdown";
}

export const ComplianceDownloadContainer = ({
  scanId,
  complianceId,
  reportType,
  compact = false,
  disabled = false,
  orientation = "row",
  buttonWidth = "auto",
  presentation = "buttons",
}: ComplianceDownloadContainerProps) => {
  const [isDownloadingCsv, setIsDownloadingCsv] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const isIconWidth = buttonWidth === "icon";
  const isDropdown = presentation === "dropdown";

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
      // The helper picks the right endpoint internally: single-version
      // frameworks hit `/scans/{id}/{reportType}`, CIS variants hit
      // `/scans/{id}/cis/{complianceId}`. The container stays
      // framework-agnostic so future multi-variant frameworks only need a
      // new ``reportType`` constant, not a new branch here.
      await downloadCompliancePdf(scanId, reportType, toast, { complianceId });
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const buttonClassName = cn(
    "border-button-primary text-button-primary hover:bg-button-primary/10",
    compact &&
      !isIconWidth &&
      "h-7 px-2 text-xs sm:w-full sm:justify-center sm:px-2.5",
    orientation === "column" && !isIconWidth && "w-full",
    isIconWidth && "size-10 rounded-lg p-0",
  );
  const labelClassName = isIconWidth
    ? "sr-only"
    : compact
      ? "sr-only sm:not-sr-only"
      : undefined;
  const showTooltip = compact || isIconWidth;

  return (
    <div
      className={cn(
        "flex",
        orientation === "column"
          ? "flex-col items-start"
          : compact
            ? "w-full justify-end sm:w-auto"
            : "flex-row",
      )}
    >
      {isDropdown ? (
        <ActionDropdown
          variant={isIconWidth ? "bordered" : "table"}
          ariaLabel="Open compliance export actions"
        >
          <ActionDropdownItem
            icon={
              <FileTextIcon
                className={isDownloadingCsv ? "animate-download-icon" : ""}
              />
            }
            label="Download CSV report"
            onSelect={handleDownloadCsv}
            disabled={disabled || isDownloadingCsv}
          />
          {reportType && (
            <ActionDropdownItem
              icon={
                <DownloadIcon
                  className={isDownloadingPdf ? "animate-download-icon" : ""}
                />
              }
              label="Download PDF report"
              onSelect={handleDownloadPdf}
              disabled={disabled || isDownloadingPdf}
            />
          )}
        </ActionDropdown>
      ) : (
        <div
          className={cn(
            "flex gap-2",
            orientation === "column"
              ? isIconWidth
                ? "flex-col items-start"
                : "flex-col items-stretch"
              : compact
                ? "w-full flex-wrap items-center justify-end sm:w-auto sm:flex-nowrap"
                : "flex-row flex-wrap items-center",
          )}
        >
          <Tooltip>
            <TooltipTrigger asChild>
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
                <span className={labelClassName}>CSV</span>
              </Button>
            </TooltipTrigger>
            {showTooltip && (
              <TooltipContent>Download CSV report</TooltipContent>
            )}
          </Tooltip>
          {reportType && (
            <Tooltip>
              <TooltipTrigger asChild>
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
                  <span className={labelClassName}>PDF</span>
                </Button>
              </TooltipTrigger>
              {showTooltip && (
                <TooltipContent>Download PDF report</TooltipContent>
              )}
            </Tooltip>
          )}
        </div>
      )}
    </div>
  );
};
