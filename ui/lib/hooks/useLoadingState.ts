import { useEffect, useState } from "react";

interface UseLoadingStateOptions {
  /**
   * Minimum duration in milliseconds that the loading state will be active
   * This helps prevent "flickering" of loading states for very fast operations
   */
  minimumLoadingTime?: number;

  /**
   * Delay before showing the loading state
   * This helps prevent "flickering" of loading states for very fast operations
   */
  showLoadingDelay?: number;

  /**
   * Initial loading state
   */
  initialState?: boolean;
}

/**
 * A hook to manage loading states with minimum duration and delay options
 * to prevent flickering for very fast operations
 */
export function useLoadingState({
  minimumLoadingTime = 500,
  showLoadingDelay = 200,
  initialState = false,
}: UseLoadingStateOptions = {}) {
  const [isLoading, setIsLoading] = useState(initialState);
  const [internalIsLoading, setInternalIsLoading] = useState(initialState);

  // Handle the delayed loading state
  useEffect(() => {
    let showLoadingTimeout: NodeJS.Timeout;
    let hideLoadingTimeout: NodeJS.Timeout;

    if (internalIsLoading) {
      // Only show loading indicator after delay to prevent flickering
      showLoadingTimeout = setTimeout(() => {
        setIsLoading(true);
      }, showLoadingDelay);
    } else {
      // When loading is done, keep the loading state for minimum time
      // to prevent flickering between loading states
      if (isLoading) {
        hideLoadingTimeout = setTimeout(() => {
          setIsLoading(false);
        }, minimumLoadingTime);
      }
    }

    return () => {
      clearTimeout(showLoadingTimeout);
      clearTimeout(hideLoadingTimeout);
    };
  }, [internalIsLoading, isLoading, minimumLoadingTime, showLoadingDelay]);

  return {
    /** Public loading state, considering minimum time and delay */
    isLoading,

    /** Start loading */
    startLoading: () => setInternalIsLoading(true),

    /** Stop loading (actual display might continue for minimumLoadingTime) */
    stopLoading: () => setInternalIsLoading(false),

    /** Set loading state directly */
    setLoading: setInternalIsLoading,
  };
}
