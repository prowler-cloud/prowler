"use client";

import { usePathname } from "next/navigation";

import { useMountEffect } from "@/hooks/use-mount-effect";
import { usePageReadyStore } from "@/store/page-ready";

/**
 * Invisible marker rendered inside a page's post-Suspense (data-loaded) content.
 * While it is unmounted the route counts as "still loading", which the navbar uses
 * to keep the product-tour replay icon disabled until the page's requests resolve.
 * Mounting marks the route ready; unmounting (navigation / in-page re-suspense) clears it.
 */
export function PageReady() {
  const pathname = usePathname();
  const markReady = usePageReadyStore((state) => state.markReady);
  const clearReady = usePageReadyStore((state) => state.clearReady);

  useMountEffect(() => {
    markReady(pathname);
    return () => clearReady(pathname);
  });

  return null;
}
