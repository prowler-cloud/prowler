"use client";

import { useSyncExternalStore } from "react";

const canMatchMedia = () =>
  typeof window !== "undefined" && typeof window.matchMedia === "function";

// SSR-safe media query subscription (server snapshot is always false).
export function useMediaQuery(query: string): boolean {
  return useSyncExternalStore(
    (onChange) => {
      if (!canMatchMedia()) return () => {};
      const mediaQueryList = window.matchMedia(query);
      mediaQueryList.addEventListener("change", onChange);
      return () => mediaQueryList.removeEventListener("change", onChange);
    },
    () => (canMatchMedia() ? window.matchMedia(query).matches : false),
    () => false,
  );
}
