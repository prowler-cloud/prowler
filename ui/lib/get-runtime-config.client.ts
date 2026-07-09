"use client";

import {
  EMPTY_RUNTIME_PUBLIC_CONFIG,
  RUNTIME_CONFIG_SCRIPT_ID,
  type RuntimePublicConfig,
} from "@/lib/runtime-config.shared";

let cached: RuntimePublicConfig | null = null;

// Explicit per-key copy (not a spread) so unexpected island keys can't leak through.
const pickConfig = (
  parsed: Partial<RuntimePublicConfig>,
): RuntimePublicConfig => ({
  sentryDsn: parsed.sentryDsn ?? null,
  sentryEnvironment: parsed.sentryEnvironment ?? null,
  googleTagManagerId: parsed.googleTagManagerId ?? null,
  apiBaseUrl: parsed.apiBaseUrl ?? null,
  apiDocsUrl: parsed.apiDocsUrl ?? null,
  posthogKey: parsed.posthogKey ?? null,
  posthogHost: parsed.posthogHost ?? null,
  reoDevClientId: parsed.reoDevClientId ?? null,
  billingCloudEnable: parsed.billingCloudEnable ?? false,
});

// Reads the <head> island once (memoized); all-null during SSR or if it's
// missing/malformed, so callers can treat every integration as disabled.
export function getRuntimeConfigClient(): RuntimePublicConfig {
  if (cached) return cached;
  if (typeof document === "undefined") return EMPTY_RUNTIME_PUBLIC_CONFIG;

  const el = document.getElementById(RUNTIME_CONFIG_SCRIPT_ID);
  let resolved: RuntimePublicConfig;
  try {
    resolved = el?.textContent
      ? pickConfig(JSON.parse(el.textContent) as Partial<RuntimePublicConfig>)
      : EMPTY_RUNTIME_PUBLIC_CONFIG;
  } catch {
    resolved = EMPTY_RUNTIME_PUBLIC_CONFIG;
  }

  cached = resolved;
  return resolved;
}
