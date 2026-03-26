"use client";

import { useRef } from "react";

import {
  adaptFindingGroupResourcesResponse,
  getFindingGroupResources,
  getLatestFindingGroupResources,
} from "@/actions/finding-groups";
import { useMountEffect } from "@/hooks/use-mount-effect";
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
  /** Reset pagination and re-fetch page 1 (e.g. after muting). */
  refresh: () => void;
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

      // Discard stale response if checkId or filters changed during fetch
      if (signal.aborted) {
        onSetLoadingRef.current(false);
        return;
      }

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
      if (!signal.aborted) {
        console.error("Error fetching resources:", error);
        onSetLoadingRef.current(false);
      }
    } finally {
      isLoadingRef.current = false;
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

    const nextPage = pageRef.current + 1;
    pageRef.current = nextPage;
    fetchPage(nextPage, true, currentCheckIdRef.current, signal);
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

  return { sentinelRef, refresh };
}
