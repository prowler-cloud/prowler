"use client";

import { useSyncExternalStore } from "react";

import { getRuntimeConfigClient } from "@/lib/get-runtime-config.client";
import {
  EMPTY_RUNTIME_PUBLIC_CONFIG,
  type RuntimePublicConfig,
} from "@/lib/runtime-config.shared";

// The runtime config lives in a <head> data island that only exists in the
// browser, so the server render — and the first client render during
// hydration — must see the empty config to stay in sync. useSyncExternalStore
// returns getServerSnapshot during SSR/hydration and swaps to the island value
// afterwards, so config-derived markup never triggers a hydration mismatch.
// Both snapshots are referentially stable (memoized getter / module constant),
// which useSyncExternalStore requires.
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
