"use client";

import { useEffect } from "react";

import { useUIStore } from "@/store/ui/ui-store";

interface StoreInitializerProps {
  values: {
    hasProviders?: boolean;
    // Add more properties here as needed
    // otherProperty?: string;
  };
}

// Define which keys from values should be watched
const STORE_KEYS: (keyof StoreInitializerProps["values"])[] = [
  "hasProviders",
  // Add more keys here as the store grows
];

export function StoreInitializer({ values }: StoreInitializerProps) {
  const setHasProviders = useUIStore((state) => state.setHasProviders);

  useEffect(
    () => {
      // Initialize store values from server
      if (values.hasProviders !== undefined) {
        setHasProviders(values.hasProviders);
      }
      // Add more setters here as needed in the future
    },
    STORE_KEYS.map((key) => values[key]),
  );

  return null;
}
