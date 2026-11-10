"use client";

import { useEffect, useRef, useState } from "react";

import { getFindingById } from "@/actions/findings";
import { expandFindingWithRelationships } from "@/lib/finding-detail";
import { FindingProps } from "@/types";

interface UseFindingDetailsReturn {
  findingDetails: FindingProps | null;
  findingDetailLoading: boolean;
  navigateToFinding: (findingId: string) => Promise<void>;
  resetFindingDetails: () => void;
}

export function useFindingDetails(): UseFindingDetailsReturn {
  const [findingDetails, setFindingDetails] = useState<FindingProps | null>(
    null,
  );
  const [findingDetailLoading, setFindingDetailLoading] = useState(false);
  const findingFetchRef = useRef<AbortController | null>(null);

  useEffect(() => {
    return () => {
      findingFetchRef.current?.abort();
    };
  }, []);

  const navigateToFinding = async (findingId: string) => {
    if (findingFetchRef.current) {
      findingFetchRef.current.abort();
    }
    // Each lookup checks its own controller: the ref already points at a
    // newer lookup by the time a slow one answers.
    const controller = new AbortController();
    findingFetchRef.current = controller;
    setFindingDetailLoading(true);

    try {
      const findingData = await getFindingById(
        findingId,
        "resources,scan.provider",
      );

      if (controller.signal.aborted) {
        return;
      }

      if (findingData?.data) {
        setFindingDetails(expandFindingWithRelationships(findingData));
      }
    } catch (error) {
      if (error instanceof Error && error.name === "AbortError") {
        return;
      }
      console.error("Error fetching finding:", error);
    } finally {
      if (!controller.signal.aborted) {
        setFindingDetailLoading(false);
      }
    }
  };

  const resetFindingDetails = () => {
    findingFetchRef.current?.abort();
    setFindingDetails(null);
    setFindingDetailLoading(false);
  };

  return {
    findingDetails,
    findingDetailLoading,
    navigateToFinding,
    resetFindingDetails,
  };
}
