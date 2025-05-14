"use client";

import { useRouter, useSearchParams } from "next/navigation";
import { useEffect, useState } from "react";

import { getProvider } from "@/actions/providers";
import { getScan } from "@/actions/scans";
import { getTask } from "@/actions/task";
import { ScanDetail } from "@/components/scans/table";
import { Alert } from "@/components/ui/alert/Alert";
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
        // eslint-disable-next-line no-console
        console.error("Error in fetchScanDetails:", error);
      } finally {
        setIsLoading(false);
      }
    };

    fetchScanDetails();
  }, [entityId]);

  if (isLoading) {
    return (
      <Alert className="text-center text-small font-bold text-gray-500">
        Scan details are loading and will be available once the scan is
        completed.
      </Alert>
    );
  }

  if (!scanDetails) {
    return <div>No scan details available</div>;
  }

  return <ScanDetail scanDetails={scanDetails} />;
};
