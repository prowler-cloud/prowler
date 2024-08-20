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
      <CardBody className="flex flex-row items-center space-x-4 justify-between">
        <div className="flex space-x-4 items-center w-full">
          <Image
            src={getComplianceIcon(title)}
            alt={`${title} logo`}
            className="rounded-md p-1 border-gray-300 border-1 bg-white object-contain h-10 w-10 min-w-10"
          />
          <div className="flex flex-col w-full">
            <h4 className="font-bold text-md 3xl:text-lg leading-5">{title}</h4>
            <Progress
              label="Your Rating:"
              size="sm"
              aria-label="Your Rating"
              value={ratingPercentage}
              showValueLabel={true}
              className="mt-2 font-semibold"
              color={getRatingColor(ratingPercentage)}
            />
            <div className="flex justify-between mt-2">
              <small>
                <span className="font-semibold mr-1">
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
