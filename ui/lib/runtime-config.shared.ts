// Side-effect-free shape shared by the server and client readers (no
// server-only code, so it's safe to import from the client bundle).
export interface RuntimePublicConfig {
  sentryDsn: string | null;
  sentryEnvironment: string | null;
  googleTagManagerId: string | null;
  apiBaseUrl: string | null;
  apiDocsUrl: string | null;
  posthogKey: string | null; // reserved
  posthogHost: string | null; // reserved
  reoDevClientId: string | null; // reserved
  cloudEnabled: boolean;
  cloudBillingEnabled: boolean;
  stripePublishableKey: string | null; // reserved
  stripePublishableKeyV2: string | null; // reserved
}

export const RUNTIME_CONFIG_SCRIPT_ID = "__PROWLER_RUNTIME_CONFIG__";

// Env var for the Prowler Cloud flag; shared so the island producer
// (lib/runtime-config.ts), the isCloud() env fallback (lib/shared/env.ts)
// and the boot checks (lib/env.ts) can never drift.
export const CLOUD_ENABLED_ENV = "UI_CLOUD_ENABLED" as const;

// All-null fallback (SSR or parse failure).
export const EMPTY_RUNTIME_PUBLIC_CONFIG: RuntimePublicConfig = {
  sentryDsn: null,
  sentryEnvironment: null,
  googleTagManagerId: null,
  apiBaseUrl: null,
  apiDocsUrl: null,
  posthogKey: null,
  posthogHost: null,
  reoDevClientId: null,
  cloudEnabled: false,
  cloudBillingEnabled: false,
  stripePublishableKey: null,
  stripePublishableKeyV2: null,
};

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
  cloudEnabled: parsed.cloudEnabled ?? false,
  cloudBillingEnabled: parsed.cloudBillingEnabled ?? false,
  stripePublishableKey: parsed.stripePublishableKey ?? null,
  stripePublishableKeyV2: parsed.stripePublishableKeyV2 ?? null,
});

// Reads and validates the <head> island. Null when there is no DOM (server /
// edge), no island (jsdom unit tests), or the JSON is malformed — callers
// choose the fallback. Deliberately uncached: a module-level cache would
// leak state across jsdom tests.
export function readRuntimeConfigIsland(): RuntimePublicConfig | null {
  if (typeof document === "undefined") return null;
  const el = document.getElementById(RUNTIME_CONFIG_SCRIPT_ID);
  if (!el?.textContent) return null;
  try {
    return pickConfig(
      JSON.parse(el.textContent) as Partial<RuntimePublicConfig>,
    );
  } catch {
    return null;
  }
}
