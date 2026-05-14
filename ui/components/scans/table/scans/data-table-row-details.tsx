"use client";

import { useEffect, useState } from "react";

import { getProvider } from "@/actions/providers";
import { getScan } from "@/actions/scans";
import { getTask } from "@/actions/task";
import { ScanDetail } from "@/components/scans/table";
import { checkTaskStatus } from "@/lib";
import { ScanProps } from "@/types";

import { SkeletonScanDetail } from "./skeleton-scan-detail";

export const DataTableRowDetails = ({ entityId }: { entityId: string }) => {
  const [scanDetails, setScanDetails] = useState<ScanProps | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchScanDetails = async () => {
      try {
        const result = await getScan(entityId);

        const taskId = result.data.relationships.task?.data?.id;
        const providerId = result.data.relationships.provider?.data?.id;

        let providerDetails = null;
        if (providerId) {
          const formData = new FormData();
          formData.append("id", providerId);
          const providerResult = await getProvider(formData);
          providerDetails = providerResult.data;
        }

        if (taskId) {
          const taskResult = await checkTaskStatus(taskId);

          if (taskResult.completed !== undefined) {
            const task = await getTask(taskId);
            setScanDetails({
              ...result.data,
              taskDetails: task.data,
              providerDetails: providerDetails,
            });
          }
        } else {
          setScanDetails({
            ...result.data,
            providerDetails: providerDetails,
          });
        }
      } catch (error) {
        console.error("Error in fetchScanDetails:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchScanDetails();
  }, [entityId]);

  if (isLoading) {
    return <SkeletonScanDetail />;
  }

  if (!scanDetails) {
    return <div>No scan details available</div>;
  }

  return <ScanDetail scanDetails={scanDetails} />;
};
