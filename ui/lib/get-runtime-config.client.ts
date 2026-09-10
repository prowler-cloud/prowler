"use client";

import {
  EMPTY_RUNTIME_PUBLIC_CONFIG,
  readRuntimeConfigIsland,
  type RuntimePublicConfig,
} from "@/lib/runtime-config.shared";

let cached: RuntimePublicConfig | null = null;

// Reads the <head> island once (memoized); all-null during SSR or if it's
// missing/malformed, so callers can treat every integration as disabled.
export function getRuntimeConfigClient(): RuntimePublicConfig {
  if (cached) return cached;
  cached = readRuntimeConfigIsland() ?? EMPTY_RUNTIME_PUBLIC_CONFIG;
  return cached;
}
