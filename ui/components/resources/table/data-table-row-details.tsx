"use client";

import { CircleArrowLeft } from "lucide-react";
import { useEffect, useState } from "react";

import { getFindings } from "@/actions/findings";
import { getResourceById } from "@/actions/resources";
import { FindingDetail } from "@/components/findings/table";
import { CustomButton } from "@/components/ui/custom";
import { createDict } from "@/lib";
import { FindingProps, ResourceApiResponse, ResourceProps } from "@/types";

import { SkeletonFindingDetails } from "../skeleton/skeleton-finding-details";
import { ResourceDetail } from "./resource-detail";

export const DataTableRowDetails = ({
  resourceId,
  resourceData,
}: {
  resourceId: string;
  resourceData: ResourceProps;
}) => {
  const [isLoading, setIsLoading] = useState(true);
  const [resourceDetails, setResourceDetails] =
    useState<ResourceApiResponse | null>(null);
  const [findingDetail, setFindingDetails] = useState<FindingProps | null>(
    null,
  );
  const [isFindingsLoading, setIsFindingsLoading] = useState(false);

  useEffect(() => {
    const fetchScanDetails = async () => {
      try {
        const result = await getResourceById(resourceId);
        setResourceDetails(result);
        setIsLoading(false);
      } catch (error) {
        // eslint-disable-next-line no-console
        console.error("Error in fetchScanDetails:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchScanDetails();
  }, [resourceId]);

  const fetchFindingsDetails = async (
    uid: string,
    inserted_at: string,
    resourceId: string,
  ) => {
    setIsFindingsLoading(true);

    try {
      const findingsData = await getFindings({
        filters: {
          "filter[uid]": uid,
          "filter[inserted_at]": inserted_at,
          "filter[id]": resourceId,
        },
      });

      // Create dictionaries for resources, scans, and providers
      const resourceDict = createDict("resources", findingsData);
      const scanDict = createDict("scans", findingsData);
      const providerDict = createDict("providers", findingsData);

      // Expand each finding with its corresponding resource, scan, and provider
      const expandedFindings = findingsData?.data
        ? findingsData.data.map((finding: FindingProps) => {
            const scan = scanDict[finding.relationships?.scan?.data?.id];
            const resource =
              resourceDict[finding.relationships?.resources?.data?.[0]?.id];
            const provider =
              providerDict[scan?.relationships?.provider?.data?.id];

            return {
              ...finding,
              relationships: { scan, resource, provider },
            };
          })
        : [];

      setFindingDetails(expandedFindings[0]);
    } catch (error) {
      console.error("Failed to fetch findings:", error);
      setFindingDetails(null);
    } finally {
      setIsFindingsLoading(false);
    }
  };

  return (
    <>
      {findingDetail && findingDetail?.attributes ? (
        <>
          <div className="mb-2">
            <CustomButton
              ariaLabel="Back"
              className="w-full md:w-fit"
              onPress={() => {
                setFindingDetails(null);
              }}
              variant="dashed"
              size="md"
              startContent={<CircleArrowLeft size={22} />}
              radius="sm"
            >
              Back
            </CustomButton>
          </div>
          <FindingDetail findingDetails={findingDetail} />
        </>
      ) : isFindingsLoading ? (
        <SkeletonFindingDetails />
      ) : (
        <ResourceDetail
          resourceData={resourceData}
          resourceDetails={resourceDetails}
          isLoading={isLoading}
          fetchFindings={fetchFindingsDetails}
        />
      )}
    </>
  );
};
