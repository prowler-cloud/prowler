"use client";

import { useEffect, useState } from "react";

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

  useEffect(() => {
    if (!isCloud()) return;
    let active = true;
    const load = async () => {
      try {
        const discovery = await getInstalledRegistryProviderOptions();
        if (active) setResult(discovery);
      } catch {
        if (active) setResult({ status: REGISTRY_PROVIDER_DISCOVERY.UNKNOWN });
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
