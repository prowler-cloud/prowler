"use client";

import { useEffect, useRef, useState } from "react";

import {
  adaptFindingsByResourceResponse,
  getLatestFindingsByResourceUid,
  type ResourceDrawerFinding,
} from "@/actions/findings";
import { FindingResourceRow } from "@/types";

// Keep fast carousel navigations in a loading state for one short beat so
// React doesn't batch away the skeleton frame when switching resources.
const MIN_NAVIGATION_SKELETON_MS = 300;

/**
 * Check-level metadata that is identical across all resources for a given check.
 * Extracted once on first successful fetch and kept stable during navigation.
 */
export interface CheckMeta {
  checkId: string;
  checkTitle: string;
  risk: string;
  description: string;
  complianceFrameworks: string[];
  categories: string[];
  remediation: ResourceDrawerFinding["remediation"];
  additionalUrls: string[];
}

function extractCheckMeta(finding: ResourceDrawerFinding): CheckMeta {
  return {
    checkId: finding.checkId,
    checkTitle: finding.checkTitle,
    risk: finding.risk,
    description: finding.description,
    complianceFrameworks: finding.complianceFrameworks,
    categories: finding.categories,
    remediation: finding.remediation,
    additionalUrls: finding.additionalUrls,
  };
}

interface UseResourceDetailDrawerOptions {
  resources: FindingResourceRow[];
  checkId: string;
  totalResourceCount?: number;
  onRequestMoreResources?: () => void;
  initialIndex?: number | null;
  includeMutedInOtherFindings?: boolean;
}

interface UseResourceDetailDrawerReturn {
  isOpen: boolean;
  isLoading: boolean;
  isNavigating: boolean;
  checkMeta: CheckMeta | null;
  currentIndex: number;
  totalResources: number;
  currentFinding: ResourceDrawerFinding | null;
  otherFindings: ResourceDrawerFinding[];
  allFindings: ResourceDrawerFinding[];
  openDrawer: (index: number) => void;
  closeDrawer: () => void;
  navigatePrev: () => void;
  navigateNext: () => void;
  /** Clear cache for current resource and re-fetch (e.g. after muting). */
  refetchCurrent: () => void;
}

/**
 * Manages the resource detail drawer state, fetching, and navigation.
 *
 * Caches findings per resourceUid in a Map ref so navigating prev/next
 * doesn't re-fetch already-visited resources.
 */
export function useResourceDetailDrawer({
  resources,
  checkId,
  totalResourceCount,
  onRequestMoreResources,
  initialIndex = null,
  includeMutedInOtherFindings = false,
}: UseResourceDetailDrawerOptions): UseResourceDetailDrawerReturn {
  const [isOpen, setIsOpen] = useState(initialIndex !== null);
  const [isLoading, setIsLoading] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(initialIndex ?? 0);
  const [findings, setFindings] = useState<ResourceDrawerFinding[]>([]);
  const [isNavigating, setIsNavigating] = useState(false);

  const cacheRef = useRef<Map<string, ResourceDrawerFinding[]>>(new Map());
  const checkMetaRef = useRef<CheckMeta | null>(null);
  const fetchControllerRef = useRef<AbortController | null>(null);
  const navigationTimeoutRef = useRef<ReturnType<typeof setTimeout> | null>(
    null,
  );
  const navigationStartedAtRef = useRef<number | null>(null);

  const clearNavigationTimeout = () => {
    if (navigationTimeoutRef.current !== null) {
      clearTimeout(navigationTimeoutRef.current);
      navigationTimeoutRef.current = null;
    }
  };

  const finishNavigation = () => {
    clearNavigationTimeout();
    setIsLoading(false);

    const navigationStartedAt = navigationStartedAtRef.current;
    if (navigationStartedAt === null) {
      navigationStartedAtRef.current = null;
      setIsNavigating(false);
      return;
    }

    const elapsed = Date.now() - navigationStartedAt;
    const remaining = Math.max(0, MIN_NAVIGATION_SKELETON_MS - elapsed);

    if (remaining === 0) {
      navigationStartedAtRef.current = null;
      setIsNavigating(false);
      return;
    }

    navigationTimeoutRef.current = setTimeout(() => {
      setIsNavigating(false);
      navigationStartedAtRef.current = null;
      navigationTimeoutRef.current = null;
    }, remaining);
  };

  const startNavigation = () => {
    clearNavigationTimeout();
    navigationStartedAtRef.current = Date.now();
    setIsNavigating(true);
  };

  // Abort any in-flight request on unmount to prevent state updates
  // on an already-unmounted component.
  useEffect(() => {
    return () => {
      fetchControllerRef.current?.abort();
      clearNavigationTimeout();
      navigationStartedAtRef.current = null;
    };
  }, []);

  const fetchFindings = async (resourceUid: string) => {
    // Abort any in-flight request to prevent stale data from out-of-order responses
    fetchControllerRef.current?.abort();
    clearNavigationTimeout();
    const controller = new AbortController();
    fetchControllerRef.current = controller;

    // Check cache first
    const cached = cacheRef.current.get(resourceUid);
    if (cached) {
      if (!checkMetaRef.current) {
        const main = cached.find((f) => f.checkId === checkId) ?? cached[0];
        if (main) checkMetaRef.current = extractCheckMeta(main);
      }
      setFindings(cached);
      finishNavigation();
      return;
    }

    setIsLoading(true);
    try {
      const response = await getLatestFindingsByResourceUid({
        resourceUid,
        includeMuted: includeMutedInOtherFindings,
      });

      // Discard stale response if a newer request was started
      if (controller.signal.aborted) return;

      const adapted = adaptFindingsByResourceResponse(response);
      cacheRef.current.set(resourceUid, adapted);

      // Extract check-level metadata once (stable across all resources)
      if (!checkMetaRef.current) {
        const main = adapted.find((f) => f.checkId === checkId) ?? adapted[0];
        if (main) checkMetaRef.current = extractCheckMeta(main);
      }

      setFindings(adapted);
    } catch (error) {
      if (!controller.signal.aborted) {
        console.error("Error fetching findings for resource:", error);
        setFindings([]);
      }
    } finally {
      if (!controller.signal.aborted) {
        finishNavigation();
      }
    }
  };

  useEffect(() => {
    if (initialIndex === null) {
      return;
    }

    const resource = resources[initialIndex];
    if (!resource) {
      return;
    }

    fetchFindings(resource.resourceUid);
    // Only initialize once on mount for deep-link/inline entry points.
    // User-driven navigations use openDrawer/navigateTo afterwards.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openDrawer = (index: number) => {
    const resource = resources[index];
    if (!resource) return;

    clearNavigationTimeout();
    navigationStartedAtRef.current = null;
    setCurrentIndex(index);
    setIsOpen(true);
    setIsNavigating(false);
    setFindings([]);
    fetchFindings(resource.resourceUid);
  };

  const closeDrawer = () => {
    setIsOpen(false);
  };

  const refetchCurrent = () => {
    const resource = resources[currentIndex];
    if (!resource) return;
    cacheRef.current.delete(resource.resourceUid);
    startNavigation();
    setFindings([]);
    fetchFindings(resource.resourceUid);
  };

  const navigateTo = (index: number) => {
    const resource = resources[index];
    if (!resource) return;

    setCurrentIndex(index);
    startNavigation();
    setFindings([]);
    fetchFindings(resource.resourceUid);
  };

  const navigatePrev = () => {
    if (currentIndex > 0) {
      navigateTo(currentIndex - 1);
    }
  };

  const navigateNext = () => {
    const total = totalResourceCount ?? resources.length;
    if (currentIndex >= total - 1) return;

    // Pre-fetch more resources when nearing the end of loaded data
    if (currentIndex >= resources.length - 3) {
      onRequestMoreResources?.();
    }

    // Navigate if the next resource is already loaded
    if (currentIndex < resources.length - 1) {
      navigateTo(currentIndex + 1);
    }
  };

  // The finding whose checkId matches the drill-down's checkId
  const currentFinding =
    findings.find((f) => f.checkId === checkId) ?? findings[0] ?? null;

  // "Other Findings For This Resource" intentionally shows only FAIL entries,
  // while currentFinding (the drilled-down one) can be any status (FAIL, MANUAL, PASS…).
  const otherFindings = (
    currentFinding
      ? findings.filter((f) => f.id !== currentFinding.id)
      : findings
  ).filter((f) => f.status === "FAIL");

  return {
    isOpen,
    isLoading,
    isNavigating,
    checkMeta: checkMetaRef.current,
    currentIndex,
    totalResources: totalResourceCount ?? resources.length,
    currentFinding,
    otherFindings,
    allFindings: findings,
    openDrawer,
    closeDrawer,
    navigatePrev,
    navigateNext,
    refetchCurrent,
  };
}
