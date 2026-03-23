"use client";

import { useEffect, useRef } from "react";

import {
  adaptFindingGroupResourcesResponse,
  getFindingGroupResources,
  getLatestFindingGroupResources,
} from "@/actions/finding-groups";
import { FindingResourceRow } from "@/types";

const RESOURCES_PAGE_SIZE = 20;

interface UseInfiniteResourcesOptions {
  checkId: string;
  hasDateOrScanFilter: boolean;
  filters: Record<string, string | string[] | undefined>;
  onSetResources: (resources: FindingResourceRow[], hasMore: boolean) => void;
  onAppendResources: (
    resources: FindingResourceRow[],
    hasMore: boolean,
  ) => void;
  onSetLoading: (loading: boolean) => void;
}

interface UseInfiniteResourcesReturn {
  sentinelRef: (node: HTMLDivElement | null) => void;
}

/**
 * Hook for paginated infinite-scroll loading of finding group resources.
 *
 * Uses refs for all mutable state to avoid dependency chains that
 * cause infinite re-render loops. `checkId` and `filtersKey` trigger
 * a new initial fetch via useEffect.
 */
export function useInfiniteResources({
  checkId,
  hasDateOrScanFilter,
  filters,
  onSetResources,
  onAppendResources,
  onSetLoading,
}: UseInfiniteResourcesOptions): UseInfiniteResourcesReturn {
  // Stable serialization of filters for dependency tracking
  const filtersKey = JSON.stringify(
    Object.entries(filters)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b)),
  );

  // All mutable state in refs to break dependency chains
  const pageRef = useRef(1);
  const hasMoreRef = useRef(true);
  const isLoadingRef = useRef(false);
  const currentCheckIdRef = useRef(checkId);
  const observerRef = useRef<IntersectionObserver | null>(null);

  // Store latest values in refs so the fetch function always reads current values
  // without being recreated on every render
  const hasDateOrScanRef = useRef(hasDateOrScanFilter);
  const filtersRef = useRef(filters);
  const onSetResourcesRef = useRef(onSetResources);
  const onAppendResourcesRef = useRef(onAppendResources);
  const onSetLoadingRef = useRef(onSetLoading);

  // Keep refs in sync with latest props
  hasDateOrScanRef.current = hasDateOrScanFilter;
  filtersRef.current = filters;
  onSetResourcesRef.current = onSetResources;
  onAppendResourcesRef.current = onAppendResources;
  onSetLoadingRef.current = onSetLoading;

  async function fetchPage(page: number, append: boolean, forCheckId: string) {
    if (isLoadingRef.current) return;

    isLoadingRef.current = true;
    onSetLoadingRef.current(true);

    const fetchFn = hasDateOrScanRef.current
      ? getFindingGroupResources
      : getLatestFindingGroupResources;

    try {
      const response = await fetchFn({
        checkId: forCheckId,
        page,
        pageSize: RESOURCES_PAGE_SIZE,
        filters: filtersRef.current,
      });

      // Discard stale response if checkId changed during fetch
      if (currentCheckIdRef.current !== forCheckId) return;

      const resources = adaptFindingGroupResourcesResponse(
        response,
        forCheckId,
      );
      const totalPages = response?.meta?.pagination?.pages ?? 1;
      const hasMore = page < totalPages;

      hasMoreRef.current = hasMore;

      if (append) {
        onAppendResourcesRef.current(resources, hasMore);
      } else {
        onSetResourcesRef.current(resources, hasMore);
      }
    } catch (error) {
      console.error("Error fetching resources:", error);
      if (currentCheckIdRef.current === forCheckId) {
        onSetLoadingRef.current(false);
      }
    } finally {
      isLoadingRef.current = false;
    }
  }

  // Fetch first page when checkId or filters change
  useEffect(() => {
    currentCheckIdRef.current = checkId;
    pageRef.current = 1;
    hasMoreRef.current = true;
    isLoadingRef.current = false;

    fetchPage(1, false, checkId);
  }, [checkId, filtersKey]);

  function loadNextPage() {
    if (!hasMoreRef.current || isLoadingRef.current) return;

    const nextPage = pageRef.current + 1;
    pageRef.current = nextPage;
    fetchPage(nextPage, true, currentCheckIdRef.current);
  }

  // IntersectionObserver callback
  function handleIntersection(entries: IntersectionObserverEntry[]) {
    const [entry] = entries;
    if (entry.isIntersecting) {
      loadNextPage();
    }
  }

  // Set up observer when sentinel node changes
  function sentinelRef(node: HTMLDivElement | null) {
    if (observerRef.current) {
      observerRef.current.disconnect();
      observerRef.current = null;
    }

    if (node) {
      observerRef.current = new IntersectionObserver(handleIntersection, {
        rootMargin: "200px",
      });
      observerRef.current.observe(node);
    }
  }

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (observerRef.current) {
        observerRef.current.disconnect();
      }
    };
  }, []);

  return { sentinelRef };
}
