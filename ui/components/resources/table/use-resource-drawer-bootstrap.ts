"use client";

import { useEffect, useState } from "react";

import { getResourceDrawerData } from "@/actions/resources";
import {
  applyOptimisticTriageSummaryUpdate,
  getOptimisticTriageMutedReason,
  shouldMarkFindingMutedForTriageUpdate,
} from "@/lib/finding-triage";
import { MetaDataProps } from "@/types";
import type { UpdateFindingTriageInput } from "@/types/findings-triage";
import { OrganizationResource } from "@/types/organizations";

import { ResourceFinding } from "./resource-findings-columns";

interface UseResourceDrawerBootstrapOptions {
  resourceId: string;
  resourceUid: string;
  providerId: string;
  providerType: string;
  currentPage: number;
  pageSize: number;
  searchQuery: string;
  findingsReloadNonce: number;
}

interface UseResourceDrawerBootstrapReturn {
  findingsData: ResourceFinding[];
  findingsMetadata: MetaDataProps | null;
  findingsLoading: boolean;
  hasInitiallyLoaded: boolean;
  providerOrg: OrganizationResource | null;
  resourceTags: Record<string, string>;
  patchTriageUpdate: (input: UpdateFindingTriageInput) => void;
}

export function useResourceDrawerBootstrap({
  resourceId,
  resourceUid,
  providerId,
  providerType,
  currentPage,
  pageSize,
  searchQuery,
  findingsReloadNonce,
}: UseResourceDrawerBootstrapOptions): UseResourceDrawerBootstrapReturn {
  const [findingsData, setFindingsData] = useState<ResourceFinding[]>([]);
  const [findingsMetadata, setFindingsMetadata] =
    useState<MetaDataProps | null>(null);
  const [resourceTags, setResourceTags] = useState<Record<string, string>>({});
  const [findingsLoading, setFindingsLoading] = useState(true);
  const [hasInitiallyLoaded, setHasInitiallyLoaded] = useState(false);
  const [providerOrg, setProviderOrg] = useState<OrganizationResource | null>(
    null,
  );

  const patchTriageUpdate = (input: UpdateFindingTriageInput) => {
    setFindingsData((findings) =>
      findings.map((finding) => {
        if (!finding.triage || finding.triage.findingId !== input.findingId) {
          return finding;
        }

        const shouldMarkMuted = shouldMarkFindingMutedForTriageUpdate(input);

        return {
          ...finding,
          triage: applyOptimisticTriageSummaryUpdate(finding.triage, input),
          attributes: {
            ...finding.attributes,
            muted: shouldMarkMuted ? true : finding.attributes.muted,
            muted_reason:
              shouldMarkMuted && input.isMuted !== true && input.status
                ? getOptimisticTriageMutedReason(input.status)
                : finding.attributes.muted_reason,
          },
        };
      }),
    );
  };

  useEffect(() => {
    let cancelled = false;

    const loadResourceDrawerData = async () => {
      setFindingsLoading(true);

      try {
        const drawerData = await getResourceDrawerData({
          resourceId,
          resourceUid,
          providerId,
          providerType,
          page: currentPage,
          pageSize,
          query: searchQuery,
        });

        if (cancelled) return;

        setResourceTags(drawerData.resourceTags);
        setProviderOrg(drawerData.providerOrg);
        setFindingsMetadata(drawerData.findingsMeta as MetaDataProps | null);
        setFindingsData(drawerData.findings as ResourceFinding[]);
      } catch (error) {
        if (cancelled) return;
        console.error("Error loading resource drawer data:", error);
        setResourceTags({});
        setProviderOrg(null);
        setFindingsData([]);
        setFindingsMetadata(null);
      } finally {
        if (!cancelled) {
          setFindingsLoading(false);
          setHasInitiallyLoaded(true);
        }
      }
    };

    if (resourceUid) {
      loadResourceDrawerData();
    }

    return () => {
      cancelled = true;
    };
  }, [
    currentPage,
    findingsReloadNonce,
    pageSize,
    providerId,
    providerType,
    resourceId,
    resourceUid,
    searchQuery,
  ]);

  return {
    findingsData,
    findingsMetadata,
    findingsLoading,
    hasInitiallyLoaded,
    providerOrg,
    resourceTags,
    patchTriageUpdate,
  };
}
