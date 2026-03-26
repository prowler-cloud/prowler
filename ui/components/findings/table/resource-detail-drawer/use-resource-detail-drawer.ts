"use client";

import { useRef, useState } from "react";

import {
  adaptFindingsByResourceResponse,
  getLatestFindingsByResourceUid,
  type ResourceDrawerFinding,
} from "@/actions/findings";
import { FindingResourceRow } from "@/types";

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
}: UseResourceDetailDrawerOptions): UseResourceDetailDrawerReturn {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [findings, setFindings] = useState<ResourceDrawerFinding[]>([]);
  const [isNavigating, setIsNavigating] = useState(false);

  const cacheRef = useRef<Map<string, ResourceDrawerFinding[]>>(new Map());
  const checkMetaRef = useRef<CheckMeta | null>(null);
  const fetchControllerRef = useRef<AbortController | null>(null);

  const fetchFindings = async (resourceUid: string) => {
    // Abort any in-flight request to prevent stale data from out-of-order responses
    fetchControllerRef.current?.abort();
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
      setIsLoading(false);
      setIsNavigating(false);
      return;
    }

    setIsLoading(true);
    try {
      const response = await getLatestFindingsByResourceUid({ resourceUid });

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
        // Don't clear findings — keep previous data as fallback during navigation
      }
    } finally {
      if (!controller.signal.aborted) {
        setIsLoading(false);
        setIsNavigating(false);
      }
    }
  };

  const openDrawer = (index: number) => {
    const resource = resources[index];
    if (!resource) return;

    setCurrentIndex(index);
    setIsOpen(true);
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
    setIsNavigating(true);
    fetchFindings(resource.resourceUid);
  };

  const navigateTo = (index: number) => {
    const resource = resources[index];
    if (!resource) return;

    setCurrentIndex(index);
    setIsNavigating(true);
    fetchFindings(resource.resourceUid);
  };

  const navigatePrev = () => {
    if (currentIndex > 0) {
      navigateTo(currentIndex - 1);
    }
  };

  const navigateNext = () => {
    if (currentIndex < resources.length - 1) {
      navigateTo(currentIndex + 1);

      // Pre-fetch more resources when nearing the end
      if (currentIndex >= resources.length - 3) {
        onRequestMoreResources?.();
      }
    }
  };

  // The finding whose checkId matches the drill-down's checkId
  const currentFinding =
    findings.find((f) => f.checkId === checkId) ?? findings[0] ?? null;

  // All other findings for this resource
  const otherFindings = currentFinding
    ? findings.filter((f) => f.id !== currentFinding.id)
    : findings;

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
