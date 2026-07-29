"use client";

import { useSyncExternalStore } from "react";

import { getRuntimeConfigClient } from "@/lib/get-runtime-config.client";
import {
  EMPTY_RUNTIME_PUBLIC_CONFIG,
  type RuntimePublicConfig,
} from "@/lib/runtime-config.shared";

// The island is browser-only, so SSR and the first hydration render must see
// the empty config to avoid a mismatch; useSyncExternalStore swaps to the
// island value afterwards. Both snapshots must be referentially stable.
const subscribe = () => () => {}; // config is immutable after load — never notifies

const getServerSnapshot = (): RuntimePublicConfig =>
  EMPTY_RUNTIME_PUBLIC_CONFIG;

export function useRuntimeConfig(): RuntimePublicConfig {
  return useSyncExternalStore(
    subscribe,
    getRuntimeConfigClient,
    getServerSnapshot,
  );
}
