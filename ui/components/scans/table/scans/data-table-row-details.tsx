"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import { getScan } from "@/actions/scans";
import { getTask } from "@/actions/task";
import { ScanDetail, SkeletonTableScans } from "@/components/scans/table";
import { checkTaskStatus } from "@/lib";
import { ScanProps } from "@/types";

export const DataTableRowDetails = ({ entityId }: { entityId: string }) => {
  const router = useRouter();
  const searchParams = useSearchParams();
  const [scanDetails, setScanDetails] = useState<ScanProps | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Add scanId to URL
    const params = new URLSearchParams(searchParams.toString());
    params.set("scanId", entityId);
    router.push(`?${params.toString()}`, { scroll: false });

    // Cleanup function: remove scanId from URL when component unmounts
    return () => {
      const newParams = new URLSearchParams(searchParams.toString());
      newParams.delete("scanId");
      router.push(`?${newParams.toString()}`, { scroll: false });
    };
  }, [entityId, router, searchParams]);

  useEffect(() => {
    const fetchScanDetails = async () => {
      try {
        const result = await getScan(entityId);

        const taskId = result.data.relationships.task?.data?.id;

        if (taskId) {
          const taskResult = await checkTaskStatus(taskId);

          if (taskResult.completed !== undefined) {
            const task = await getTask(taskId);
            setScanDetails({
              ...result.data,
              taskDetails: task.data,
            });
          }
        } else {
          setScanDetails(result.data);
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
    return <SkeletonTableScans />;
  }

  if (!scanDetails) {
    return <div>No scan details available</div>;
  }

  return <ScanDetail scanDetails={scanDetails} />;
};
