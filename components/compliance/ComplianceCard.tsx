import { Card, CardBody, Progress } from "@nextui-org/react";
import Image from "next/image";
import React from "react";

import { getComplianceIcon } from "../icons";

interface ComplianceCardProps {
  title: string;
  passingRequirements: number;
  totalRequirements: number;
  prevPassingRequirements: number;
  prevTotalRequirements: number;
}

export const ComplianceCard: React.FC<ComplianceCardProps> = ({
  title,
  passingRequirements,
  totalRequirements,
  prevPassingRequirements,
  prevTotalRequirements,
}) => {
  const ratingPercentage = Math.floor(
    (passingRequirements / totalRequirements) * 100,
  );

  const prevRatingPercentage = Math.floor(
    (prevPassingRequirements / prevTotalRequirements) * 100,
  );

  const getScanChange = () => {
    const scanDifference = ratingPercentage - prevRatingPercentage;
    if (scanDifference < 0 && scanDifference <= -1) {
      return `${scanDifference}% from last scan`;
    }
    if (scanDifference > 0 && scanDifference >= 1) {
      return `+${scanDifference}% from last scan`;
    }
    return "No change from last scan";
  };

  const getRatingColor = (ratingPercentage: number) => {
    if (ratingPercentage <= 10) {
      return "danger";
    }
    if (ratingPercentage <= 40) {
      return "warning";
    }
    return "success";
  };

  return (
    <Card fullWidth isPressable isHoverable shadow="sm">
      <CardBody className="flex flex-row items-center justify-between space-x-4">
        <div className="flex w-full items-center space-x-4">
          <Image
            src={getComplianceIcon(title)}
            alt={`${title} logo`}
            className="h-10 w-10 min-w-10 rounded-md border-1 border-gray-300 bg-white object-contain p-1"
          />
          <div className="flex w-full flex-col">
            <h4 className="text-md font-bold leading-5 3xl:text-lg">{title}</h4>
            <Progress
              label="Your Rating:"
              size="sm"
              aria-label="Your Rating"
              value={ratingPercentage}
              showValueLabel={true}
              className="mt-2 font-semibold"
              color={getRatingColor(ratingPercentage)}
            />
            <div className="mt-2 flex justify-between">
              <small>
                <span className="mr-1 font-semibold">
                  {passingRequirements} / {totalRequirements}
                </span>
                Passing Requirements
              </small>
              <small>{getScanChange()}</small>
            </div>
          </div>
        </div>
      </CardBody>
    </Card>
  );
};
