"use client";

import { useEffect, useState } from "react";

import { getProviders } from "@/actions/providers";

export const useHasProviders = () => {
  const [hasProviders, setHasProviders] = useState<boolean | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const checkProviders = async () => {
      try {
        const providersData = await getProviders({
          pageSize: 1, // Only need to check if at least one exists
        });

        const providersExist = !!(
          providersData?.data && providersData.data.length > 0
        );
        setHasProviders(providersExist);
      } catch (error) {
        console.error("Error checking providers:", error);
        setHasProviders(false);
      } finally {
        setIsLoading(false);
      }
    };

    checkProviders();
  }, []);

  return { hasProviders, isLoading };
};
