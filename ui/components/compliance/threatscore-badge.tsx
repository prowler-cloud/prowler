"use client";

import { DownloadIcon, FileTextIcon } from "lucide-react";
import { useRouter, useSearchParams } from "next/navigation";
import { useState } from "react";

import type { SectionScores } from "@/actions/overview/threat-score";
import { ThreatScoreLogo } from "@/components/compliance/threatscore-logo";
import { Card, CardContent } from "@/components/shadcn/card/card";
import {
  ActionDropdown,
  ActionDropdownItem,
} from "@/components/shadcn/dropdown";
import { Progress } from "@/components/shadcn/progress";
import { toast } from "@/components/ui";
import { COMPLIANCE_REPORT_TYPES } from "@/lib/compliance/compliance-report-types";
import {
  getScoreColor,
  getScoreIndicatorClass,
  getScoreTextClass,
} from "@/lib/compliance/score-utils";
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
  sectionScores,
}: ThreatScoreBadgeProps) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [isDownloadingCsv, setIsDownloadingCsv] = useState(false);
  const [isDownloadingPdf, setIsDownloadingPdf] = useState(false);

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

    const regionFilter = searchParams.get("filter[region__in]");
    if (regionFilter) {
      params.set("filter[region__in]", regionFilter);
    }

    router.push(`${path}?${params.toString()}`);
  };

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
    if (isDownloadingPdf) return;
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

  return (
    <Card variant="base" padding="md" className="relative gap-4">
      <CardContent className="flex flex-col gap-4 p-0 pr-14 lg:flex-row lg:items-start lg:gap-6">
        {/* Clickable ThreatScore button */}
        <button
          className="border-border-neutral-secondary bg-bg-neutral-tertiary hover:border-border-neutral-primary hover:bg-bg-neutral-secondary flex shrink-0 cursor-pointer flex-row items-center justify-between gap-4 rounded-xl border p-3 pr-12 text-left transition-colors lg:pr-3"
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
              className="border-border-neutral-secondary h-2.5 w-24 border"
              indicatorClassName={getScoreIndicatorClass(getScoreColor(score))}
            />
          </div>
        </button>

        {/* Pillar breakdown — always visible */}
        {sectionScores && Object.keys(sectionScores).length > 0 && (
          <div className="border-border-neutral-secondary flex-1 space-y-2 border-t pt-3 lg:border-t-0 lg:border-l lg:pt-0 lg:pl-6">
            {Object.entries(sectionScores)
              .sort(([, a], [, b]) => a - b)
              .map(([section, sectionScore]) => (
                <div key={section} className="flex items-center gap-2 text-xs">
                  <span className="text-text-neutral-secondary w-1/3 min-w-0 shrink-0 truncate lg:w-1/4">
                    {section}
                  </span>
                  <Progress
                    aria-label={`${section} score`}
                    value={sectionScore}
                    className="border-border-neutral-secondary h-2 min-w-16 flex-1 border"
                    indicatorClassName={getScoreIndicatorClass(
                      getScoreColor(sectionScore),
                    )}
                  />
                  <span
                    className={`w-12 shrink-0 text-right font-medium ${getScoreTextClass(sectionScore)}`}
                  >
                    {sectionScore.toFixed(1)}%
                  </span>
                </div>
              ))}
          </div>
        )}
      </CardContent>

      {/* ActionDropdown for downloads — top-right */}
      <div className="absolute top-3 right-4">
        <ActionDropdown
          variant="bordered"
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
          />
          <ActionDropdownItem
            icon={
              <DownloadIcon
                className={isDownloadingPdf ? "animate-download-icon" : ""}
              />
            }
            label="Download PDF report"
            onSelect={handleDownloadPdf}
          />
        </ActionDropdown>
      </div>
    </Card>
  );
};
