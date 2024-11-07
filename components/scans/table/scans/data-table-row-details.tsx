"use client";

import { useEffect, useState } from "react";

import { getScan } from "@/actions/scans";
import { ScanDetail, SkeletonTableScans } from "@/components/scans/table";
import { ScanProps } from "@/types";

export const DataTableRowDetails = ({ entityId }: { entityId: string }) => {
  const [scanDetails, setScanDetails] = useState<ScanProps | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const fetchScanDetails = async () => {
      try {
        const result = await getScan(entityId);
        setScanDetails(result?.data);
      } catch (error) {
        console.error("Error fetching scan details:", error);
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
