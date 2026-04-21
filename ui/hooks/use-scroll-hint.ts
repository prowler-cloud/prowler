"use client";

import { useCallback, useEffect, useState } from "react";

interface UseScrollHintOptions {
  enabled?: boolean;
  refreshToken?: string | number;
}

/**
 * Detects whether a scrollable container has overflow using an
 * IntersectionObserver on a sentinel element placed at the end of the content.
 *
 * Uses callback refs (stored in state) so the observer is set up only after
 * the DOM elements actually mount — critical for Radix Dialog portals where
 * useRef would be null when the first useEffect fires.
 *
 * When the sentinel is NOT visible inside the container → content overflows
 * and the user hasn't scrolled to the bottom → show hint.
 */
export function useScrollHint({
  enabled = true,
  refreshToken,
}: UseScrollHintOptions = {}) {
  const [containerEl, setContainerEl] = useState<HTMLDivElement | null>(null);
  const [sentinelEl, setSentinelEl] = useState<HTMLDivElement | null>(null);
  const [showScrollHint, setShowScrollHint] = useState(false);

  useEffect(() => {
    if (!enabled || !containerEl || !sentinelEl) {
      setShowScrollHint(false);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        setShowScrollHint(!entry.isIntersecting);
      },
      {
        root: containerEl,
        // Small margin so the hint hides slightly before the absolute bottom
        rootMargin: "0px 0px 4px 0px",
        threshold: 0,
      },
    );

    observer.observe(sentinelEl);

    return () => observer.disconnect();
  }, [enabled, refreshToken, containerEl, sentinelEl]);

  // Stable callback refs — setState setters never change identity
  const containerRef = useCallback(
    (node: HTMLDivElement | null) => setContainerEl(node),
    [],
  );
  const sentinelRef = useCallback(
    (node: HTMLDivElement | null) => setSentinelEl(node),
    [],
  );

  return {
    containerRef,
    sentinelRef,
    showScrollHint,
  };
}
