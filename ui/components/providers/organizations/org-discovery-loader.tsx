"use client";

import { Loader2, RefreshCw } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { getDiscovery } from "@/actions/organizations/organizations";
import {
  buildOrgTreeData,
  getSelectableAccountIds,
} from "@/actions/organizations/organizations.adapter";
import { Button } from "@/components/shadcn";
import { useOrgSetupStore } from "@/store/organizations/store";
import { DISCOVERY_STATUS, DiscoveryResult } from "@/types/organizations";

const POLL_INTERVAL_MS = 3000;
const MAX_RETRIES = 60;

interface OrgDiscoveryLoaderProps {
  onDiscoveryComplete: () => void;
}

export function OrgDiscoveryLoader({
  onDiscoveryComplete,
}: OrgDiscoveryLoaderProps) {
  const { organizationId, discoveryId, setDiscovery, setSelectedAccountIds } =
    useOrgSetupStore();

  const [status, setStatus] = useState<string>(DISCOVERY_STATUS.PENDING);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const retryCountRef = useRef(0);
  const pollRef = useRef<ReturnType<typeof setTimeout> | null>(null);

  const pollDiscovery = async () => {
    if (!organizationId || !discoveryId) return;

    const result = await getDiscovery(organizationId, discoveryId);

    if (result?.error) {
      setStatus(DISCOVERY_STATUS.FAILED);
      setErrorMessage(result.error);
      return;
    }

    const discoveryStatus = result.data.attributes.status;
    setStatus(discoveryStatus);

    if (discoveryStatus === DISCOVERY_STATUS.SUCCEEDED) {
      const discoveryResult = result.data.attributes.result as DiscoveryResult;

      // Store discovery result
      setDiscovery(discoveryId, discoveryResult);

      // Pre-select all selectable accounts
      const selectableIds = getSelectableAccountIds(discoveryResult);
      setSelectedAccountIds(selectableIds);

      // Pre-build tree data to ensure it's valid
      buildOrgTreeData(discoveryResult);

      onDiscoveryComplete();
      return;
    }

    if (discoveryStatus === DISCOVERY_STATUS.FAILED) {
      setErrorMessage(
        result.data.attributes.error ?? "Discovery failed. Please try again.",
      );
      return;
    }

    // Still pending or running — schedule next poll
    if (retryCountRef.current >= MAX_RETRIES) {
      setStatus(DISCOVERY_STATUS.FAILED);
      setErrorMessage("Discovery timed out. Please try again.");
      return;
    }
    retryCountRef.current += 1;
    pollRef.current = setTimeout(pollDiscovery, POLL_INTERVAL_MS);
  };

  useEffect(() => {
    pollDiscovery();

    return () => {
      if (pollRef.current) clearTimeout(pollRef.current);
    };
    // Only run on mount
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRetry = () => {
    setStatus(DISCOVERY_STATUS.PENDING);
    setErrorMessage(null);
    retryCountRef.current = 0;
    pollDiscovery();
  };

  if (status === DISCOVERY_STATUS.FAILED || errorMessage) {
    return (
      <div className="flex flex-col items-center gap-4 py-12">
        <div className="border-destructive/50 bg-destructive/10 text-destructive rounded-md border px-6 py-4 text-center text-sm">
          {errorMessage ?? "An unknown error occurred during discovery."}
        </div>
        <Button variant="outline" onClick={handleRetry}>
          <RefreshCw className="mr-2 size-4" />
          Retry Discovery
        </Button>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-4 py-12">
      <Loader2 className="text-primary size-8 animate-spin" />
      <div className="text-center">
        <p className="text-sm font-medium">
          Discovering your AWS Organization...
        </p>
        <p className="text-muted-foreground text-xs">
          This may take a few moments
        </p>
      </div>
    </div>
  );
}
