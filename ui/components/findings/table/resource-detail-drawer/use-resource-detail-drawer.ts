"use client";

import { useEffect, useRef, useState } from "react";

import {
  adaptFindingsByResourceResponse,
  getFindingById,
  getLatestFindingsByResourceUid,
  type ResourceDrawerFinding,
} from "@/actions/findings";
import {
  applyOptimisticTriageSummaryUpdate,
  getOptimisticTriageMutedReason,
  shouldMarkFindingMutedForTriageUpdate,
} from "@/lib/finding-triage";
import { FindingResourceRow } from "@/types";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";

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
  totalResourceCount?: number;
  onRequestMoreResources?: () => void;
  initialIndex?: number | null;
  canLoadOtherFindings?: boolean;
  includeMutedInOtherFindings?: boolean;
}

interface UseResourceDetailDrawerReturn {
  isOpen: boolean;
  isLoading: boolean;
  isNavigating: boolean;
  checkMeta: CheckMeta | null;
  currentIndex: number;
  totalResources: number;
  currentResource: FindingResourceRow | null;
  currentFinding: ResourceDrawerFinding | null;
  otherFindings: ResourceDrawerFinding[];
  openDrawer: (index: number) => void;
  closeDrawer: () => void;
  navigatePrev: () => void;
  navigateNext: () => void;
  /** Clear cache for current resource and re-fetch (e.g. after muting). */
  refetchCurrent: () => void;
  /** Patch triage state locally after a successful lightweight triage update. */
  patchTriageUpdate: (input: UpdateFindingTriageInput) => void;
}

/**
 * Manages the resource detail drawer state, fetching, and navigation.
 *
 * Caches findings per findingId in a Map ref so navigating prev/next
 * doesn't re-fetch already-visited resources.
 */
export function useResourceDetailDrawer({
  resources,
  totalResourceCount,
  onRequestMoreResources,
  initialIndex = null,
  canLoadOtherFindings = true,
  includeMutedInOtherFindings = false,
}: UseResourceDetailDrawerOptions): UseResourceDetailDrawerReturn {
  const [isOpen, setIsOpen] = useState(initialIndex !== null);
  const [isLoading, setIsLoading] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(initialIndex ?? 0);
  const [currentFinding, setCurrentFinding] =
    useState<ResourceDrawerFinding | null>(null);
  const [otherFindings, setOtherFindings] = useState<ResourceDrawerFinding[]>(
    [],
  );
  const [isNavigating, setIsNavigating] = useState(false);

  const currentFindingCacheRef = useRef<
    Map<string, ResourceDrawerFinding | null>
  >(new Map());
  const otherFindingsCacheRef = useRef<Map<string, ResourceDrawerFinding[]>>(
    new Map(),
  );
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

  const resetCurrentResourceState = () => {
    setCurrentFinding(null);
    setOtherFindings([]);
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

  const fetchFindings = async (resource: FindingResourceRow) => {
    // Abort any in-flight request to prevent stale data from out-of-order responses
    fetchControllerRef.current?.abort();
    clearNavigationTimeout();
    const controller = new AbortController();
    fetchControllerRef.current = controller;

    const { findingId, resourceUid } = resource;

    const fetchCurrentFinding = async () => {
      const cached = currentFindingCacheRef.current.get(findingId);
      if (cached !== undefined) {
        return cached;
      }

      const response = await getFindingById(
        findingId,
        "resources,scan.provider",
        { source: "resource-detail-drawer" },
      );

      const adapted = adaptFindingsByResourceResponse(response);
      const finding =
        adapted.find((item) => item.id === findingId) ?? adapted[0] ?? null;

      currentFindingCacheRef.current.set(findingId, finding);

      return finding;
    };

    const fetchOtherFindings = async () => {
      if (!canLoadOtherFindings || !resourceUid) {
        return [];
      }

      const cached = otherFindingsCacheRef.current.get(resourceUid);
      if (cached) {
        return cached;
      }

      const response = await getLatestFindingsByResourceUid({
        resourceUid,
        pageSize: 50,
        includeMuted: includeMutedInOtherFindings,
      });
      const adapted = adaptFindingsByResourceResponse(response);

      otherFindingsCacheRef.current.set(resourceUid, adapted);

      return adapted;
    };

    setIsLoading(true);
    try {
      const [nextCurrentFinding, nextOtherFindings] = await Promise.all([
        fetchCurrentFinding(),
        fetchOtherFindings(),
      ]);

      // Discard stale response if a newer request was started
      if (controller.signal.aborted) return;

      checkMetaRef.current = nextCurrentFinding
        ? extractCheckMeta(nextCurrentFinding)
        : null;

      setCurrentFinding(nextCurrentFinding);
      // The API already filters to status=FAIL (see getLatestFindingsByResourceUid).
      // Only need to drop the current finding from the list.
      setOtherFindings(
        nextOtherFindings.filter((finding) => finding.id !== findingId),
      );
    } catch (_error) {
      if (!controller.signal.aborted) {
        checkMetaRef.current = null;
        setCurrentFinding(null);
        setOtherFindings([]);
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

    fetchFindings(resource);
    // Only initialize once on mount for deep-link/inline entry points.
    // User-driven navigations use openDrawer/navigateTo afterwards.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const openDrawer = (index: number) => {
    const resource = resources[index];
    if (!resource) return;

    setCurrentIndex(index);
    setIsOpen(true);
    startNavigation();
    resetCurrentResourceState();
    fetchFindings(resource);
  };

  const closeDrawer = () => {
    setIsOpen(false);
  };

  const refetchCurrent = () => {
    const resource = resources[currentIndex];
    if (!resource) return;
    currentFindingCacheRef.current.delete(resource.findingId);
    otherFindingsCacheRef.current.delete(resource.resourceUid);
    startNavigation();
    resetCurrentResourceState();
    fetchFindings(resource);
  };

  const patchFindingTriage = (
    finding: ResourceDrawerFinding | null,
    input: UpdateFindingTriageInput,
  ): ResourceDrawerFinding | null => {
    if (!finding?.triage || finding.triage.findingId !== input.findingId) {
      return finding;
    }

    const shouldMarkMuted = shouldMarkFindingMutedForTriageUpdate(input);

    return {
      ...finding,
      isMuted: shouldMarkMuted ? true : finding.isMuted,
      mutedReason:
        shouldMarkMuted && input.isMuted !== true && input.status
          ? getOptimisticTriageMutedReason(input.status)
          : finding.mutedReason,
      triage: applyOptimisticTriageSummaryUpdate(finding.triage, input),
    };
  };

  const patchTriageUpdate = (input: UpdateFindingTriageInput) => {
    currentFindingCacheRef.current.forEach((finding, key) => {
      const patchedFinding = patchFindingTriage(finding, input);
      if (patchedFinding !== finding) {
        currentFindingCacheRef.current.set(key, patchedFinding);
      }
    });

    otherFindingsCacheRef.current.forEach((findings, key) => {
      const patchedFindings = findings.map((finding) =>
        patchFindingTriage(finding, input),
      );

      if (
        patchedFindings.some((finding, index) => finding !== findings[index])
      ) {
        otherFindingsCacheRef.current.set(
          key,
          patchedFindings.filter(
            (finding): finding is ResourceDrawerFinding => finding !== null,
          ),
        );
      }
    });

    setCurrentFinding((finding) => patchFindingTriage(finding, input));
    setOtherFindings((findings) =>
      findings
        .map((finding) => patchFindingTriage(finding, input))
        .filter(
          (finding): finding is ResourceDrawerFinding => finding !== null,
        ),
    );
  };

  const navigateTo = (index: number) => {
    const resource = resources[index];
    if (!resource) return;

    setCurrentIndex(index);
    startNavigation();
    resetCurrentResourceState();
    fetchFindings(resource);
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

  const currentResource = resources[currentIndex];

  return {
    isOpen,
    isLoading,
    isNavigating,
    checkMeta: checkMetaRef.current,
    currentIndex,
    totalResources: totalResourceCount ?? resources.length,
    currentResource: currentResource ?? null,
    currentFinding,
    otherFindings,
    openDrawer,
    closeDrawer,
    navigatePrev,
    navigateNext,
    refetchCurrent,
    patchTriageUpdate,
  };
}
