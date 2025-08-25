"use client";

import { useEffect } from "react";

import { useUIStore } from "@/store/ui/store";

interface StoreInitializerProps {
  values: {
    hasProviders?: boolean;
    // Add more properties here as needed
    // otherProperty?: string;
  };
}

export function StoreInitializer({ values }: StoreInitializerProps) {
  const setHasProviders = useUIStore((state) => state.setHasProviders);

  useEffect(() => {
    // Initialize store values from server
    if (values.hasProviders !== undefined) {
      setHasProviders(values.hasProviders);
    }
    // Add more setters here as needed in the future
  }, [values.hasProviders, setHasProviders]);

  return null;
}
