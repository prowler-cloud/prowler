"use client";

import { useState } from "react";

import { useMountEffect } from "./use-mount-effect";

export interface ScrollportPin {
  /** Visible content width of the scrollport (padding excluded). */
  width: number;
  /** Left padding of the scrollport, for a sticky child that keeps the inset. */
  left: number;
}

/**
 * Measures a horizontally scrolling container once on mount and on resize, so
 * a sticky child can span exactly the visible area instead of the full
 * scroll width. Resolves to null until measured (or without ResizeObserver).
 */
export function useScrollportPin(
  resolveScrollport: () => Element | null | undefined,
): ScrollportPin | null {
  const [pin, setPin] = useState<ScrollportPin | null>(null);

  useMountEffect(() => {
    const scrollport = resolveScrollport();
    if (
      !(scrollport instanceof HTMLElement) ||
      typeof ResizeObserver === "undefined"
    ) {
      return;
    }
    const measure = () => {
      const styles = getComputedStyle(scrollport);
      const paddingLeft = parseFloat(styles.paddingLeft);
      setPin({
        width:
          scrollport.clientWidth -
          paddingLeft -
          parseFloat(styles.paddingRight),
        left: paddingLeft,
      });
    };
    measure();
    const observer = new ResizeObserver(measure);
    observer.observe(scrollport);
    return () => observer.disconnect();
  });

  return pin;
}
