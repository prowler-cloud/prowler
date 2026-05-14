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

interface UseFindingGroupResourcesOptions {
  checkId: string;
  hasDateOrScanFilter: boolean;
  filters: Record<string, string | string[] | undefined>;
  onSetResources: (resources: FindingResourceRow[], hasMore: boolean) => void;
  onAppendResources: (
    resources: FindingResourceRow[],
    hasMore: boolean,
  ) => void;
  onSetLoading: (loading: boolean) => void;
  scrollContainerRef?: React.RefObject<HTMLElement | null>;
}

interface UseFindingGroupResourcesReturn {
  sentinelRef: (node: HTMLDivElement | null) => void;
  refresh: () => void;
  loadMore: () => void;
  totalCount: number | null;
}

export function useFindingGroupResources({
  checkId,
  hasDateOrScanFilter,
  filters,
  onSetResources,
  onAppendResources,
  onSetLoading,
  scrollContainerRef,
}: UseFindingGroupResourcesOptions): UseFindingGroupResourcesReturn {
  const pageRef = useRef(1);
  const hasMoreRef = useRef(true);
  const isLoadingRef = useRef(true);
  const currentCheckIdRef = useRef(checkId);
  const controllerRef = useRef<AbortController | null>(null);
  const observerRef = useRef<IntersectionObserver | null>(null);
  const totalCountRef = useRef<number | null>(null);

  const hasDateOrScanRef = useRef(hasDateOrScanFilter);
  const filtersRef = useRef(filters);
  const onSetResourcesRef = useRef(onSetResources);
  const onAppendResourcesRef = useRef(onAppendResources);
  const onSetLoadingRef = useRef(onSetLoading);

  currentCheckIdRef.current = checkId;
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

      pageRef.current = page;
      hasMoreRef.current = hasMore;

      if (append) {
        onAppendResourcesRef.current(resources, hasMore);
      } else {
        onSetResourcesRef.current(resources, hasMore);
      }
    } catch (error) {
      if (!signal.aborted) {
        console.error("Error fetching finding group resources:", error);
        onSetLoadingRef.current(false);
      }
    } finally {
      if (!signal.aborted) {
        isLoadingRef.current = false;
      }
    }
  }

  useMountEffect(() => {
    const controller = new AbortController();
    controllerRef.current = controller;

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
    ) {
      return;
    }

    fetchPage(pageRef.current + 1, true, currentCheckIdRef.current, signal);
  }

  function handleIntersection(entries: IntersectionObserverEntry[]) {
    const [entry] = entries;
    if (entry.isIntersecting) {
      loadNextPage();
    }
  }

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
