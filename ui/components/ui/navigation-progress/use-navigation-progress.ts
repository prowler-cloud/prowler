"use client";

import { usePathname, useSearchParams } from "next/navigation";
import { useEffect, useRef, useSyncExternalStore } from "react";

// Simple global state for progress bar
interface ProgressState {
  isLoading: boolean;
  progress: number;
}

let state: ProgressState = { isLoading: false, progress: 0 };
const listeners = new Set<() => void>();

function notify() {
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

function getSnapshot(): ProgressState {
  return state;
}

// Cached server snapshot to avoid infinite loop with useSyncExternalStore
const SERVER_SNAPSHOT: ProgressState = { isLoading: false, progress: 0 };

function getServerSnapshot(): ProgressState {
  return SERVER_SNAPSHOT;
}

let progressInterval: ReturnType<typeof setInterval> | null = null;
let timeoutId: ReturnType<typeof setTimeout> | null = null;

/**
 * Start the progress bar animation.
 * Progress increases quickly at first, then slows down as it approaches 90%.
 * If already loading, restarts from 0.
 */
export function startProgress() {
  // Clear any pending reset timeout
  if (timeoutId) {
    clearTimeout(timeoutId);
    timeoutId = null;
  }

  if (progressInterval) {
    clearInterval(progressInterval);
  }

  // Always restart from 0
  state = { isLoading: true, progress: 0 };
  notify();

  // Animate progress: fast at first, slower as it approaches 90%
  progressInterval = setInterval(() => {
    if (state.progress < 90) {
      const increment = (90 - state.progress) * 0.1;
      state = { ...state, progress: Math.min(90, state.progress + increment) };
      notify();
    }
  }, 100);
}

/**
 * Complete the progress bar animation.
 * Jumps to 100% and then hides.
 */
export function completeProgress() {
  if (progressInterval) {
    clearInterval(progressInterval);
    progressInterval = null;
  }

  // Clear any pending reset timeout
  if (timeoutId) {
    clearTimeout(timeoutId);
  }

  state = { isLoading: false, progress: 100 };
  notify();

  // Reset after animation completes
  timeoutId = setTimeout(() => {
    state = { isLoading: false, progress: 0 };
    notify();
    timeoutId = null;
  }, 200);
}

/**
 * Cancel the progress bar immediately without animation.
 * Use when navigation is cancelled (e.g., clicking same URL).
 */
export function cancelProgress() {
  if (progressInterval) {
    clearInterval(progressInterval);
    progressInterval = null;
  }

  if (timeoutId) {
    clearTimeout(timeoutId);
    timeoutId = null;
  }

  // Immediately hide without animation
  state = { isLoading: false, progress: 0 };
  notify();
}

/**
 * Hook to access progress bar state.
 * Also automatically completes progress when pathname or search params change.
 */
export function useNavigationProgress() {
  const pathname = usePathname();
  const searchParams = useSearchParams();
  const prevUrl = useRef(`${pathname}?${searchParams.toString()}`);

  const currentState = useSyncExternalStore(
    subscribe,
    getSnapshot,
    getServerSnapshot,
  );

  // Complete progress when URL changes (pathname or search params)
  useEffect(() => {
    const currentUrl = `${pathname}?${searchParams.toString()}`;
    if (prevUrl.current !== currentUrl) {
      completeProgress();
      prevUrl.current = currentUrl;
    }
  }, [pathname, searchParams]);

  return currentState;
}
