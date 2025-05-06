"use client";

import { useEffect, useState } from "react";

import { getResourceById } from "@/actions/resources";
import { ResourceApiResponse, ResourceProps } from "@/types";

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

  return (
    <ResourceDetail
      resourceData={resourceData}
      resourceDetails={resourceDetails}
      isLoading={isLoading}
    />
  );
};
