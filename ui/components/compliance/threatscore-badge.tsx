"use client";

import { Card, CardBody } from "@heroui/card";
import { Progress } from "@heroui/progress";
import {
  ChevronDown,
  ChevronUp,
  DownloadIcon,
  FileTextIcon,
} from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import type { SectionScores } from "@/actions/overview/threat-score";
import { ThreatScoreLogo } from "@/components/compliance/threatscore-logo";
import { Button } from "@/components/shadcn/button/button";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/shadcn/collapsible";
import { toast } from "@/components/ui";
import { COMPLIANCE_REPORT_TYPES } from "@/lib/compliance/compliance-report-types";
import { getScoreColor, getScoreTextClass } from "@/lib/compliance/score-utils";
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
  sectionScores?: SectionScores;
}

export const ThreatScoreBadge = ({
  score,
  scanId,
  provider,
  selectedScan,
  sectionScores,
}: ThreatScoreBadgeProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);
  const [isDownloadingCsv, setIsDownloadingCsv] = useState(false);
  const [isExpanded, setIsExpanded] = useState(false);

  const complianceId = `prowler_threatscore_${provider.toLowerCase()}`;

  const handleCardClick = () => {
    const title = "ProwlerThreatScore";
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
      <CardBody className="flex flex-row flex-wrap items-center justify-between gap-3 p-4 lg:flex-col lg:items-stretch lg:justify-start">
        <button
          className="border-default-200 hover:border-default-300 hover:bg-default-50/50 flex w-full cursor-pointer flex-row items-center justify-between gap-4 rounded-lg border bg-transparent p-3 transition-all"
          onClick={handleCardClick}
          type="button"
        >
          <ThreatScoreLogo />

          <div className="flex flex-col items-end gap-1">
            <span className={`text-2xl font-bold ${getScoreTextClass(score)}`}>
              {score}%
            </span>
            <Progress
              aria-label="ThreatScore progress"
              value={score}
              color={getScoreColor(score)}
              size="sm"
              className="w-24"
            />
          </div>
        </button>

        {sectionScores && Object.keys(sectionScores).length > 0 && (
          <Collapsible
            open={isExpanded}
            onOpenChange={setIsExpanded}
            className="w-full"
          >
            <CollapsibleTrigger
              aria-label={
                isExpanded ? "Hide pillar breakdown" : "Show pillar breakdown"
              }
              className="text-default-500 hover:text-default-700 flex w-auto items-center justify-center gap-1 py-1 text-xs transition-colors lg:w-full"
            >
              {isExpanded ? (
                <>
                  <ChevronUp size={14} />
                  Hide pillar breakdown
                </>
              ) : (
                <>
                  <ChevronDown size={14} />
                  Show pillar breakdown
                </>
              )}
            </CollapsibleTrigger>
            <CollapsibleContent className="border-default-200 mt-2 w-full space-y-2 border-t pt-2">
              {Object.entries(sectionScores)
                .sort(([, a], [, b]) => a - b)
                .map(([section, sectionScore]) => (
                  <div
                    key={section}
                    className="flex items-center gap-2 text-xs"
                  >
                    <span className="text-default-600 w-1/3 min-w-0 shrink-0 truncate">
                      {section}
                    </span>
                    <Progress
                      aria-label={`${section} score`}
                      value={sectionScore}
                      color={getScoreColor(sectionScore)}
                      size="sm"
                      className="min-w-16 flex-1"
                    />
                    <span
                      className={`w-12 shrink-0 text-right font-medium ${getScoreTextClass(sectionScore)}`}
                    >
                      {sectionScore.toFixed(1)}%
                    </span>
                  </div>
                ))}
            </CollapsibleContent>
          </Collapsible>
        )}

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
