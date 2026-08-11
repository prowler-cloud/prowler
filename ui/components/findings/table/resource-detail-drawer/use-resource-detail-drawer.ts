"use client";

import { useEffect, useRef, useState } from "react";

import {
  adaptFindingsByResourceResponse,
  getFindingById,
  getFindingComplianceFrameworks,
  getLatestFindingsByResourceUid,
  type ResourceDrawerFinding,
} from "@/actions/findings";
import {
  applyOptimisticTriageSummaryUpdate,
  getOptimisticTriageMutedReason,
  isManualPassTriageUpdate,
  shouldMarkFindingMutedForTriageUpdate,
} from "@/lib/finding-triage";
import { isCloud } from "@/lib/shared/env";
import { FindingResourceRow } from "@/types";
import {
  type FindingComplianceFramework,
  WATCHLIST_SCOPE,
} from "@/types/compliance-watchlist";
import { FINDING_STATUS } from "@/types/components";
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
  /**
   * Only the frameworks the organization pinned, resolved by the API rather
   * than derived from the check's metadata: the watchlist is keyed by
   * `compliance_id`, and the display names the metadata carries cannot be
   * matched against it without guessing.
   */
  complianceFrameworks: FindingComplianceFramework[];
  categories: string[];
  remediation: ResourceDrawerFinding["remediation"];
  additionalUrls: string[];
}

/**
 * A framework name the check's own metadata carries, dressed as an API entry.
 *
 * Only for deployments without the watchlist endpoint. There is no
 * `compliance_id` behind these names, so `complianceId` holds the display name:
 * enough for the logo, which resolves by substring, and for the by-name lookup
 * the universal branch already does. `inWatchlist` is false because on such a
 * deployment there is no watchlist to be in.
 */
const fallbackFramework = (framework: string): FindingComplianceFramework => ({
  id: `fallback:${framework}`,
  complianceId: framework,
  providerType: "",
  scope: WATCHLIST_SCOPE.PROVIDER,
  framework,
  name: framework,
  version: "",
  inWatchlist: false,
});

function extractCheckMeta(
  finding: ResourceDrawerFinding,
  complianceFrameworks: FindingComplianceFramework[],
): CheckMeta {
  return {
    checkId: finding.checkId,
    checkTitle: finding.checkTitle,
    risk: finding.risk,
    description: finding.description,
    complianceFrameworks,
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
  const complianceFrameworksCacheRef = useRef<
    Map<string, FindingComplianceFramework[]>
  >(new Map());
  const otherFindingsCacheRef = useRef<Map<string, ResourceDrawerFinding[]>>(
    new Map(),
  );
  // State, not a ref: the compliance frameworks land after the panel has
  // already painted, so the strip has to re-render on its own rather than
  // depend on some other setState happening to fire in the same tick.
  const [checkMeta, setCheckMeta] = useState<CheckMeta | null>(null);
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

    const fetchComplianceFrameworks = async (
      finding: ResourceDrawerFinding | null,
    ) => {
      const cached = complianceFrameworksCacheRef.current.get(findingId);
      if (cached) {
        return cached;
      }

      // The whole strip is a Cloud feature; off Cloud there is nothing to ask
      // for, and the server action would still cost a round trip on the single
      // queue every other action in this drawer waits behind.
      const { frameworks, unavailable } = isCloud()
        ? await getFindingComplianceFrameworks(findingId, { inWatchlist: true })
        : { frameworks: [], unavailable: true };

      // The watchlist endpoint is Cloud-only. Where it does not exist, keep
      // showing what the check's own metadata already carries rather than
      // silently dropping the strip for every finding.
      const resolved =
        unavailable && finding
          ? finding.complianceFrameworks.map(fallbackFramework)
          : frameworks;

      complianceFrameworksCacheRef.current.set(findingId, resolved);

      return resolved;
    };

    setIsLoading(true);
    try {
      const [nextCurrentFinding, nextOtherFindings] = await Promise.all([
        fetchCurrentFinding(),
        fetchOtherFindings(),
      ]);

      // Discard stale response if a newer request was started
      if (controller.signal.aborted) return;

      setCheckMeta(
        nextCurrentFinding
          ? extractCheckMeta(
              nextCurrentFinding,
              // Already resolved when navigating back to a visited finding, so
              // the strip does not blink empty on the way.
              complianceFrameworksCacheRef.current.get(findingId) ?? [],
            )
          : null,
      );

      setCurrentFinding(nextCurrentFinding);
      // The API already filters to status=FAIL (see getLatestFindingsByResourceUid).
      // Only need to drop the current finding from the list.
      setOtherFindings(
        nextOtherFindings.filter((finding) => finding.id !== findingId),
      );
    } catch (_error) {
      if (!controller.signal.aborted) {
        setCheckMeta(null);
        setCurrentFinding(null);
        setOtherFindings([]);
      }
    } finally {
      if (!controller.signal.aborted) {
        finishNavigation();
      }
    }

    // Deliberately after the panel has its data, and deliberately not inside
    // the `Promise.all` above. Server actions dispatched from a client
    // component share one queue and run strictly one at a time, so bundling
    // this one added a whole round-trip to opening any finding. It is
    // supporting detail: it must never delay the panel, and its failure must
    // never empty it — hence its own `catch`, outside the block that nulls
    // everything.
    try {
      const frameworks = await fetchComplianceFrameworks(
        currentFindingCacheRef.current.get(findingId) ?? null,
      );
      if (controller.signal.aborted) return;
      setCheckMeta((current) =>
        current ? { ...current, complianceFrameworks: frameworks } : current,
      );
    } catch (_error) {
      // Leaves the strip empty; the panel stays as it is.
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
    complianceFrameworksCacheRef.current.delete(resource.findingId);
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
    const isManualPass = isManualPassTriageUpdate(input);

    return {
      ...finding,
      status: isManualPass ? FINDING_STATUS.PASS : finding.status,
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
    checkMeta,
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
