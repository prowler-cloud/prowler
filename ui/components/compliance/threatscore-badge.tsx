"use client";

import { Card, CardBody } from "@heroui/card";
import { Progress } from "@heroui/progress";
import { DownloadIcon, FileTextIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import { ThreatScoreLogo } from "@/components/compliance/threatscore-logo";
import { Button } from "@/components/shadcn/button/button";
import { toast } from "@/components/ui";
import { COMPLIANCE_REPORT_TYPES } from "@/lib/compliance/compliance-report-types";
import {
  downloadComplianceCsv,
  downloadComplianceReportPdf,
} from "@/lib/helper";
import type { ScanEntity } from "@/types/scans";

interface ThreatScoreBadgeProps {
  score: number;
  scanId: string;
  provider: string;
  selectedScan?: ScanEntity;
}

export const ThreatScoreBadge = ({
  score,
  scanId,
  provider,
  selectedScan,
}: ThreatScoreBadgeProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isDownloadingCsv, setIsDownloadingCsv] = useState(false);

  const complianceId = `prowler_threatscore_${provider.toLowerCase()}`;

  const getScoreColor = (): "success" | "warning" | "danger" => {
    if (score >= 80) return "success";
    if (score >= 40) return "warning";
    return "danger";
  };

  const getTextColor = () => {
    if (score >= 80) return "text-success";
    if (score >= 40) return "text-warning";
    return "text-text-error";
  };

  const handleCardClick = () => {
    const title = "CignifyThreatScore";
    const version = "1.0";
    const formattedTitleForUrl = encodeURIComponent(title);
    const path = `/compliance/${formattedTitleForUrl}`;
    const params = new URLSearchParams();

    params.set("complianceId", complianceId);
    params.set("version", version);
    params.set("scanId", scanId);

    if (selectedScan) {
      params.set(
        "scanData",
        JSON.stringify({
          id: selectedScan.id,
          providerInfo: selectedScan.providerInfo,
          attributes: selectedScan.attributes,
        }),
      );
    }

    const regionFilter = searchParams.get("filter[region__in]");
    if (regionFilter) {
      params.set("filter[region__in]", regionFilter);
    }

    router.push(`${path}?${params.toString()}`);
  };

  const handleDownloadPdf = async () => {
    setIsDownloadingPdf(true);
    try {
      await downloadComplianceReportPdf(
        scanId,
        COMPLIANCE_REPORT_TYPES.THREATSCORE,
        toast,
      );
    } finally {
      setIsDownloadingPdf(false);
    }
  };

  const handleDownloadCsv = async () => {
    setIsDownloadingCsv(true);
    try {
      await downloadComplianceCsv(scanId, complianceId, toast);
    } finally {
      setIsDownloadingCsv(false);
    }
  };

  return (
    <Card
      shadow="sm"
      className="border-default-200 h-full border bg-transparent"
    >
      <CardBody className="flex flex-col gap-3 p-4">
        <button
          className="border-default-200 hover:border-default-300 hover:bg-default-50/50 flex cursor-pointer flex-row items-center gap-4 rounded-lg border bg-transparent p-3 transition-all"
          onClick={handleCardClick}
          type="button"
        >
          <ThreatScoreLogo />

          <div className="flex flex-col items-end gap-1">
            <span className={`text-2xl font-bold ${getTextColor()}`}>
              {score}%
            </span>
            <Progress
              aria-label="ThreatScore progress"
              value={score}
              color={getScoreColor()}
              size="sm"
              className="w-24"
            />
          </div>
        </button>
        <div className="flex gap-2">
          <Button
            size="sm"
            variant="outline"
            className="flex-1"
            onClick={handleDownloadPdf}
            disabled={isDownloadingPdf || isDownloadingCsv}
          >
            <DownloadIcon
              size={14}
              className={isDownloadingPdf ? "animate-download-icon" : ""}
            />
            PDF
          </Button>
          <Button
            size="sm"
            variant="outline"
            className="flex-1"
            onClick={handleDownloadCsv}
            disabled={isDownloadingCsv || isDownloadingPdf}
          >
            <FileTextIcon size={14} />
            CSV
          </Button>
        </div>
      </CardBody>
    </Card>
  );
};
