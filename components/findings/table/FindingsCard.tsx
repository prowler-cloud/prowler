import { Button, Divider, Link } from "@nextui-org/react";
import React from "react";

import { FindingProps } from "@/types";
interface FindingsCardProps {
  selectedRow: FindingProps;
}

export const FindingsCard: React.FC<FindingsCardProps> = ({ selectedRow }) => {
  const { attributes, card } = selectedRow || {};
  const { CheckTitle } = attributes || {};
  const {
    resourceLink,
    resourceId,
    resourceARN,
    checkLink,
    checkId,
    type,
    scanTime,
    findingLink,
    findingId,
    details,
    riskDetails,
    riskLink,
    recommendationDetails,
    recommendationLink,
    referenceInformation,
    referenceLink,
  } = card || {};

  return (
    <>
      <div
        className={`rounded-md border bg-background transition-transform duration-300 ${selectedRow ? "w-2/5 translate-x-0 ml-2 p-3" : "translate-x-full w-0"}`}
      >
        <p className="font-bold mb-3">{CheckTitle}</p>
        <Divider />
        <div className="text-sm mt-3">
          <p className="font-bold">Resource ID:</p>
          <Link className="text-sm" href={resourceLink}>
            {resourceId}
          </Link>
          <p className="font-bold mt-3">Resource ARN:</p>
          <p>{resourceARN}</p>
          <p className="font-bold mt-3">Check ID:</p>
          <Link className="text-sm" href={checkLink}>
            {checkId}
          </Link>
          <p className="font-bold mt-3">Type:</p>
          <p>{type}</p>
          <p className="font-bold mt-3">Scan Time:</p>
          <p>{scanTime}</p>
          <p className="font-bold mt-3">Prowler Finding ID:</p>
          <Link className="text-sm" href={findingLink}>
            {findingId}
          </Link>
        </div>

        {details && (
          <div className="text-sm mt-3 rounded-md border-2 border-yellow-500 p-2">
            <p className="font-bold">Details:</p>
            <p>{details}</p>
          </div>
        )}

        {riskDetails && (
          <div className="text-sm mt-3 rounded-md border-2 border-red-500 p-2">
            <p className="font-bold flex justify-between items-center mb-2">
              <span>Risk:</span>
              {riskLink && (
                <Button
                  href={riskLink}
                  as={Link}
                  color="primary"
                  variant="flat"
                  isExternal
                  size="sm"
                  className="h-[28px] p-2"
                >
                  View Source
                </Button>
              )}
            </p>
            <p>{riskDetails}</p>
          </div>
        )}

        {recommendationDetails && (
          <div className="text-sm mt-3 rounded-md border-2 border-green-500 p-2">
            <div className="font-bold flex justify-between items-center mb-2">
              <span>Recommendation:</span>
              {recommendationLink && (
                <Button
                  href={recommendationLink}
                  as={Link}
                  color="primary"
                  variant="flat"
                  isExternal
                  size="sm"
                  className="h-[28px] p-2"
                >
                  View Source
                </Button>
              )}
            </div>
            <p>{recommendationDetails}</p>
          </div>
        )}

        {referenceInformation && (
          <div className="text-sm mt-3 rounded-md border-2 border-gray-500 p-2">
            <div className="font-bold flex justify-between items-center mb-2">
              <span>Reference Information:</span>
              {referenceLink && (
                <Button
                  href={referenceLink}
                  as={Link}
                  color="primary"
                  variant="flat"
                  isExternal
                  size="sm"
                  className="h-[28px] p-2"
                >
                  View Source
                </Button>
              )}
            </div>
            <p>{referenceInformation}</p>
          </div>
        )}
      </div>
    </>
  );
};
