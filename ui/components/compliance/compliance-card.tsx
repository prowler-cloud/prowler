"use client";

import { Progress } from "@heroui/progress";
import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";

import { Card, CardContent } from "@/components/shadcn/card/card";
import { getReportTypeForFramework } from "@/lib/compliance/compliance-report-types";
import { ScanEntity } from "@/types/scans";

import { getComplianceIcon } from "../icons";
import { ComplianceDownloadContainer } from "./compliance-download-container";

interface ComplianceCardProps {
  title: string;
  version: string;
  passingRequirements: number;
  totalRequirements: number;
  prevPassingRequirements: number;
  prevTotalRequirements: number;
  scanId: string;
  complianceId: string;
  id: string;
  selectedScan?: ScanEntity;
}

export const ComplianceCard: React.FC<ComplianceCardProps> = ({
  title,
  version,
  passingRequirements,
  totalRequirements,
  scanId,
  complianceId,
  id,
  selectedScan,
}) => {
  const searchParams = useSearchParams();
  const router = useRouter();
  const hasRegionFilter = searchParams.has("filter[region__in]");

  const formatTitle = (title: string) => {
    return title.split("-").join(" ");
  };

  const ratingPercentage = Math.floor(
    (passingRequirements / totalRequirements) * 100,
  );

  const getRatingColor = (ratingPercentage: number) => {
    if (ratingPercentage <= 10) {
      return "danger";
    }
    if (ratingPercentage <= 40) {
      return "warning";
    }
    return "success";
  };

  const navigateToDetail = () => {
    const formattedTitleForUrl = encodeURIComponent(title);
    const path = `/compliance/${formattedTitleForUrl}`;
    const params = new URLSearchParams();

    params.set("complianceId", id);
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

  return (
    <Card
      variant="base"
      padding="md"
      className="cursor-pointer transition-shadow hover:shadow-md"
      onClick={navigateToDetail}
    >
      <CardContent className="p-0">
        <div className="flex w-full items-center gap-4">
          {getComplianceIcon(title) && (
            <Image
              src={getComplianceIcon(title)}
              alt={`${title} logo`}
              className="h-10 w-10 min-w-10 rounded-md border border-gray-300 bg-white object-contain p-1"
            />
          )}
          <div className="flex w-full flex-col">
            <h4 className="text-small mb-1 leading-5 font-bold">
              {formatTitle(title)}
              {version ? ` - ${version}` : ""}
            </h4>
            <Progress
              label="Score:"
              size="sm"
              aria-label="Compliance score"
              value={ratingPercentage}
              showValueLabel={true}
              classNames={{
                track: "drop-shadow-sm border border-default",
                label: "tracking-wider font-medium text-default-600 text-xs",
                value: "text-foreground/60 -mb-2",
              }}
              color={getRatingColor(ratingPercentage)}
            />
            <div className="mt-2 flex items-center justify-between">
              <small>
                <span className="mr-1 text-xs font-semibold">
                  {passingRequirements} / {totalRequirements}
                </span>
                Passing Requirements
              </small>

              <div
                onClick={(e) => e.stopPropagation()}
                onKeyDown={(e) => {
                  if (e.key === "Enter" || e.key === " ") {
                    e.stopPropagation();
                  }
                }}
                role="group"
                tabIndex={0}
              >
                <ComplianceDownloadContainer
                  compact
                  scanId={scanId}
                  complianceId={complianceId}
                  reportType={getReportTypeForFramework(title)}
                  disabled={hasRegionFilter}
                />
              </div>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
};
