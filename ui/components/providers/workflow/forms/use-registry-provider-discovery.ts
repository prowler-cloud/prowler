"use client";

import { useEffect, useRef, useState } from "react";

import { getInstalledRegistryProviderOptions } from "@/actions/registry/registry";
import {
  REGISTRY_PROVIDER_DISCOVERY,
  type RegistryProviderDiscoveryResult,
} from "@/lib/registry/provider-options";
import { isCloud } from "@/lib/shared/env";

export function useRegistryProviderDiscovery() {
  // Local state needed: discovery and retries resolve asynchronously.
  const [result, setResult] = useState<RegistryProviderDiscoveryResult | null>(
    null,
  );
  const [attempt, setAttempt] = useState(0);
  const [isRetryingDiscovery, setIsRetryingDiscovery] = useState(false);
  // Initial, retry and artifact-change loads overlap: only the newest applies.
  const latestRequest = useRef(0);

  useEffect(() => {
    if (!isCloud()) return;
    let active = true;
    const load = async () => {
      const request = ++latestRequest.current;
      const isCurrent = () => active && request === latestRequest.current;
      try {
        const discovery = await getInstalledRegistryProviderOptions();
        if (isCurrent()) setResult(discovery);
      } catch {
        if (isCurrent())
          setResult({ status: REGISTRY_PROVIDER_DISCOVERY.UNKNOWN });
      }
    };
    void load().then(() => {
      if (active) setIsRetryingDiscovery(false);
    });
    window.addEventListener("registry-artifacts-changed", load);
    return () => {
      active = false;
      window.removeEventListener("registry-artifacts-changed", load);
    };
  }, [attempt]);

  const retryDiscovery = () => {
    if (isRetryingDiscovery) return;
    setIsRetryingDiscovery(true);
    setAttempt((current) => current + 1);
  };

  return { result, isRetryingDiscovery, retryDiscovery };
}
