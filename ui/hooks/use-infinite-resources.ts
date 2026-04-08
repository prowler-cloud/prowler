"use client";

import { useRef } from "react";

import {
  adaptFindingGroupResourcesResponse,
  getFindingGroupResources,
  getLatestFindingGroupResources,
} from "@/actions/finding-groups";
import { useMountEffect } from "@/hooks/use-mount-effect";
import { FindingResourceRow } from "@/types";

const RESOURCES_PAGE_SIZE = 10;

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
  /** Scroll container element for IntersectionObserver root. Defaults to viewport. */
  scrollContainerRef?: React.RefObject<HTMLElement | null>;
}

interface UseInfiniteResourcesReturn {
  sentinelRef: (node: HTMLDivElement | null) => void;
  /** Reset pagination and re-fetch page 1 (e.g. after muting). */
  refresh: () => void;
  /** Imperatively load the next page (e.g. from drawer navigation). */
  loadMore: () => void;
  /** Total number of resources matching current filters (from API pagination). */
  totalCount: number | null;
}

/**
 * Hook for paginated infinite-scroll loading of finding group resources.
 *
 * Uses refs for all mutable state to avoid dependency chains that
 * cause infinite re-render loops. The parent component remounts this
 * hook via key-prop when checkId or filters change.
 */
export function useInfiniteResources({
  checkId,
  hasDateOrScanFilter,
  filters,
  onSetResources,
  onAppendResources,
  onSetLoading,
  scrollContainerRef,
}: UseInfiniteResourcesOptions): UseInfiniteResourcesReturn {
  // All mutable state in refs to break dependency chains
  const pageRef = useRef(1);
  const hasMoreRef = useRef(true);
  // Start as `true` to block the IntersectionObserver from calling loadNextPage
  // before the initial fetch runs. Ref callbacks fire during commit (sync),
  // but useMountEffect fires after paint — the observer can sneak in between.
  const isLoadingRef = useRef(true);
  const currentCheckIdRef = useRef(checkId);
  const controllerRef = useRef<AbortController | null>(null);
  const observerRef = useRef<IntersectionObserver | null>(null);
  const totalCountRef = useRef<number | null>(null);

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

  async function fetchPage(
    page: number,
    append: boolean,
    forCheckId: string,
    signal: AbortSignal,
  ) {
    if (isLoadingRef.current || signal.aborted) return;

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

      // Discard stale response if aborted (e.g. Strict Mode remount)
      if (signal.aborted) {
        return;
      }

      const resources = adaptFindingGroupResourcesResponse(
        response,
        forCheckId,
      );
      const totalPages = response?.meta?.pagination?.pages ?? 1;
      const hasMore = page < totalPages;
      totalCountRef.current = response?.meta?.pagination?.count ?? null;

      // Commit the page number only after a successful (non-aborted) fetch.
      // This prevents a premature pageRef increment from loadNextPage being
      // permanently committed if a concurrent abort fires before fetchPage
      // starts executing.
      pageRef.current = page;
      hasMoreRef.current = hasMore;

      if (append) {
        onAppendResourcesRef.current(resources, hasMore);
      } else {
        onSetResourcesRef.current(resources, hasMore);
      }
    } catch (error) {
      if (!signal.aborted) {
        console.error("Error fetching resources:", error);
        onSetLoadingRef.current(false);
      }
    } finally {
      // Only release the loading guard if this fetch wasn't aborted.
      // An aborted fetch (e.g. Strict Mode cleanup) must NOT reset the flag
      // while a subsequent fetch from the remount is still in flight.
      if (!signal.aborted) {
        isLoadingRef.current = false;
      }
    }
  }

  // Fetch first page on mount — parent remounts via key-prop on checkId/filter changes
  useMountEffect(() => {
    const controller = new AbortController();
    controllerRef.current = controller;

    // Release the loading guard so fetchPage can proceed.
    // This is synchronous with the fetchPage call below, so the observer
    // cannot sneak in between these two lines.
    isLoadingRef.current = false;
    fetchPage(1, false, checkId, controller.signal);

    return () => {
      controller.abort();
      observerRef.current?.disconnect();
    };
  });

  function loadNextPage() {
    const signal = controllerRef.current?.signal;
    if (
      !hasMoreRef.current ||
      isLoadingRef.current ||
      !signal ||
      signal.aborted
    )
      return;

    // Pass the next page number as an argument without pre-committing
    // pageRef.current. The fetchPage function commits pageRef.current = page
    // only after a successful (non-aborted) response, eliminating the race
    // where a concurrent abort would leave pageRef permanently incremented.
    fetchPage(pageRef.current + 1, true, currentCheckIdRef.current, signal);
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
        root: scrollContainerRef?.current ?? null,
        rootMargin: "200px",
      });
      observerRef.current.observe(node);
    }
  }

  /** Imperatively reset and re-fetch page 1 without changing deps. */
  function refresh() {
    controllerRef.current?.abort();
    const controller = new AbortController();
    controllerRef.current = controller;

    pageRef.current = 1;
    hasMoreRef.current = true;
    isLoadingRef.current = false;

    fetchPage(1, false, currentCheckIdRef.current, controller.signal);
  }

  return {
    sentinelRef,
    refresh,
    loadMore: loadNextPage,
    totalCount: totalCountRef.current,
  };
}
