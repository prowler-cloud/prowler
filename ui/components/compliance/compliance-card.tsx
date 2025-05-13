"use client";

import { Card, CardBody, Progress } from "@nextui-org/react";
import Image from "next/image";
import { useRouter, useSearchParams } from "next/navigation";
import React from "react";

import { DownloadIconButton, toast } from "@/components/ui";
import { downloadComplianceCsv } from "@/lib/helper";

import { getComplianceIcon } from "../icons";

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
}

export const ComplianceCard: React.FC<ComplianceCardProps> = ({
  title,
  version,
  passingRequirements,
  totalRequirements,
  scanId,
  complianceId,
  id,
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

  // Calculates the percentage change in passing requirements compared to the previous scan.
  //
  // const prevRatingPercentage = Math.floor(
  //   (prevPassingRequirements / prevTotalRequirements) * 100,
  // );

  // const getScanChange = () => {
  //   const scanDifference = ratingPercentage - prevRatingPercentage;
  //   if (scanDifference < 0 && scanDifference <= -1) {
  //     return `${scanDifference}% from last scan`;
  //   }
  //   if (scanDifference > 0 && scanDifference >= 1) {
  //     return `+${scanDifference}% from last scan`;
  //   }
  //   return "No changes from last scan";
  // };

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
    router.push(
      `/compliance/${formattedTitleForUrl}?id=${id}&version=${encodeURIComponent(version)}`,
    );
  };

  return (
    <Card
      fullWidth
      isHoverable
      shadow="sm"
      isPressable
      onPress={navigateToDetail}
    >
      <CardBody className="flex flex-row items-center justify-between space-x-4 dark:bg-prowler-blue-800">
        <div className="flex w-full items-center space-x-4">
          <Image
            src={getComplianceIcon(title)}
            alt={`${title} logo`}
            className="h-10 w-10 min-w-10 rounded-md border-1 border-gray-300 bg-white object-contain p-1"
          />
          <div className="flex w-full flex-col">
            <h4 className="mb-1 text-small font-bold leading-5">
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

              <DownloadIconButton
                paramId={complianceId}
                onDownload={() =>
                  downloadComplianceCsv(scanId, complianceId, toast)
                }
                textTooltip="Download compliance CSV report"
                isDisabled={hasRegionFilter}
              />
              {/* <small>{getScanChange()}</small> */}
            </div>
          </div>
        </div>
      </CardBody>
    </Card>
  );
};
