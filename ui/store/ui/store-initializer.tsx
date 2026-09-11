"use client";

import { useEffect } from "react";

import { useUIStore } from "@/store/ui/store";

interface StoreInitializerProps {
  values: {
    hasProviders?: boolean;
    registryEligible?: boolean;
    // Add more properties here as needed
    // otherProperty?: string;
  };
}

export function StoreInitializer({ values }: StoreInitializerProps) {
  const setHasProviders = useUIStore((state) => state.setHasProviders);
  const setRegistryEligible = useUIStore((state) => state.setRegistryEligible);

  useEffect(() => {
    // Initialize store values from server
    if (values.hasProviders !== undefined) {
      setHasProviders(values.hasProviders);
    }
    if (values.registryEligible !== undefined) {
      setRegistryEligible(values.registryEligible);
    }
    // Add more setters here as needed in the future
  }, [
    values.hasProviders,
    values.registryEligible,
    setHasProviders,
    setRegistryEligible,
  ]);

  return null;
}
