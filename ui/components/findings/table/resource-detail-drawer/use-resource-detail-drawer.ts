"use client";

import { useRef, useState } from "react";

import {
  adaptFindingsByResourceResponse,
  getLatestFindingsByResourceUid,
  type ResourceDrawerFinding,
} from "@/actions/findings";
import { FindingResourceRow } from "@/types";

interface UseResourceDetailDrawerOptions {
  resources: FindingResourceRow[];
  checkId: string;
  onRequestMoreResources?: () => void;
}

interface UseResourceDetailDrawerReturn {
  isOpen: boolean;
  isLoading: boolean;
  currentIndex: number;
  totalResources: number;
  currentFinding: ResourceDrawerFinding | null;
  otherFindings: ResourceDrawerFinding[];
  allFindings: ResourceDrawerFinding[];
  openDrawer: (index: number) => void;
  closeDrawer: () => void;
  navigatePrev: () => void;
  navigateNext: () => void;
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
  onRequestMoreResources,
}: UseResourceDetailDrawerOptions): UseResourceDetailDrawerReturn {
  const [isOpen, setIsOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [currentIndex, setCurrentIndex] = useState(0);
  const [findings, setFindings] = useState<ResourceDrawerFinding[]>([]);

  const cacheRef = useRef<Map<string, ResourceDrawerFinding[]>>(new Map());

  const fetchFindings = async (resourceUid: string) => {
    // Check cache first
    const cached = cacheRef.current.get(resourceUid);
    if (cached) {
      setFindings(cached);
      setIsLoading(false);
      return;
    }

    setIsLoading(true);
    try {
      const response = await getLatestFindingsByResourceUid({ resourceUid });
      const adapted = adaptFindingsByResourceResponse(response);
      cacheRef.current.set(resourceUid, adapted);
      setFindings(adapted);
    } catch (error) {
      console.error("Error fetching findings for resource:", error);
      setFindings([]);
    } finally {
      setIsLoading(false);
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

  const navigateTo = (index: number) => {
    const resource = resources[index];
    if (!resource) return;

    setCurrentIndex(index);
    setFindings([]);
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
    currentIndex,
    totalResources: resources.length,
    currentFinding,
    otherFindings,
    allFindings: findings,
    openDrawer,
    closeDrawer,
    navigatePrev,
    navigateNext,
  };
}
