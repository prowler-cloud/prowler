"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useEffect, useSyncExternalStore } from "react";

interface ProgressState {
  isLoading: boolean;
  progress: number;
}

// Global state
let state: ProgressState = { isLoading: false, progress: 0 };
const listeners = new Set<() => void>();
let progressInterval: ReturnType<typeof setInterval> | null = null;
let timeoutId: ReturnType<typeof setTimeout> | null = null;

// Cached server snapshot to avoid infinite loop with useSyncExternalStore
const SERVER_SNAPSHOT: ProgressState = { isLoading: false, progress: 0 };

function notify() {
  listeners.forEach((listener) => listener());
}

function setState(newState: ProgressState) {
  state = newState;
  notify();
}

function clearTimers() {
  if (progressInterval) {
    clearInterval(progressInterval);
    progressInterval = null;
  }
  if (timeoutId) {
    clearTimeout(timeoutId);
    timeoutId = null;
  }
}

/**
 * Start the progress bar animation.
 * Progress increases quickly at first, then slows down as it approaches 90%.
 */
export function startProgress() {
  clearTimers();
  setState({ isLoading: true, progress: 0 });

  progressInterval = setInterval(() => {
    if (state.progress < 90) {
      const increment = (90 - state.progress) * 0.1;
      setState({
        ...state,
        progress: Math.min(90, state.progress + increment),
      });
    }
  }, 100);
}

/**
 * Complete the progress bar animation.
 * Jumps to 100% and then hides after a brief delay.
 */
export function completeProgress() {
  clearTimers();
  setState({ isLoading: false, progress: 100 });

  timeoutId = setTimeout(() => {
    setState({ isLoading: false, progress: 0 });
    timeoutId = null;
  }, 200);
}

/**
 * Cancel the progress bar immediately without animation.
 */
export function cancelProgress() {
  clearTimers();
  setState({ isLoading: false, progress: 0 });
}

/**
 * Hook to access progress bar state.
 * Automatically completes progress when URL changes.
 */
export function useNavigationProgress() {
  const pathname = usePathname();
  const searchParams = useSearchParams();

  const currentState = useSyncExternalStore(
    (listener) => {
      listeners.add(listener);
      return () => listeners.delete(listener);
    },
    () => state,
    () => SERVER_SNAPSHOT,
  );

  // Complete progress when URL changes (only if currently loading)
  useEffect(() => {
    if (state.isLoading) {
      completeProgress();
    }
  }, [pathname, searchParams]);

  return currentState;
}
