import { Divider } from "@nextui-org/react";
import clsx from "clsx";
import React from "react";

import {
  FindingsCardContent,
  FindingsCardDetail,
  FindingsCardScan,
  FindingsCardType,
} from "@/components/findings";
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
        className={clsx(
          "max-h-[calc(100vh-146px)] overflow-y-auto rounded-md border bg-background transition-all duration-300",
          {
            "ml-2 w-1/3 translate-x-0 p-3 opacity-100": selectedRow,
            "w-0 translate-x-full opacity-0": !selectedRow,
          },
        )}
      >
        <p className="mb-3 font-bold">{CheckTitle}</p>
        <Divider />

        <FindingsCardContent
          title="Resource ID:"
          url={resourceLink}
          description={resourceId}
        />
        <FindingsCardContent title="Resource ARN:" description={resourceARN} />
        <FindingsCardContent
          title="Check ID:"
          url={checkLink}
          description={checkId}
        />
        <FindingsCardType type={type} />
        <FindingsCardScan title="Scan Time:" dateTime={scanTime} />
        <FindingsCardContent
          title="Prowler Finding ID:"
          url={findingLink}
          description={findingId}
        />

        <FindingsCardDetail title="Details:" description={details} />
        <FindingsCardDetail
          title="Risk:"
          url={riskLink}
          description={riskDetails}
          type="risk"
        />
        <FindingsCardDetail
          title="Recommendation:"
          url={recommendationLink}
          description={recommendationDetails}
          type="recommendation"
        />
        <FindingsCardDetail
          title="Reference Information:"
          url={referenceLink}
          description={referenceInformation}
          type="reference"
        />
      </div>
    </>
  );
};
