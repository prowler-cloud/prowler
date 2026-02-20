"use client";

import { UIEvent, useEffect, useRef, useState } from "react";

interface UseScrollHintOptions {
  enabled?: boolean;
  refreshToken?: string | number;
}

const SCROLL_THRESHOLD_PX = 2;

function shouldShowScrollHint(element: HTMLDivElement) {
  const hasOverflow =
    element.scrollHeight - element.clientHeight > SCROLL_THRESHOLD_PX;
  const isAtBottom =
    element.scrollTop + element.clientHeight >=
    element.scrollHeight - SCROLL_THRESHOLD_PX;

  return hasOverflow && !isAtBottom;
}

export function useScrollHint({
  enabled = true,
  refreshToken,
}: UseScrollHintOptions = {}) {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [showScrollHint, setShowScrollHint] = useState(false);

  useEffect(() => {
    if (!enabled) {
      setShowScrollHint(false);
      return;
    }

    const frame = requestAnimationFrame(() => {
      const element = containerRef.current;
      if (!element) return;
      setShowScrollHint(shouldShowScrollHint(element));
    });

    const handleResize = () => {
      const element = containerRef.current;
      if (!element) return;
      setShowScrollHint(shouldShowScrollHint(element));
    };

    window.addEventListener("resize", handleResize);
    return () => {
      cancelAnimationFrame(frame);
      window.removeEventListener("resize", handleResize);
    };
  }, [enabled, refreshToken]);

  const handleScroll = (event: UIEvent<HTMLDivElement>) => {
    setShowScrollHint(shouldShowScrollHint(event.currentTarget));
  };

  return {
    containerRef,
    showScrollHint,
    handleScroll,
  };
}
