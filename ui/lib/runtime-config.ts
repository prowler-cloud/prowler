import "server-only";

import { connection } from "next/server";

import { readGatedEnv } from "@/lib/integrations";
import { type RuntimePublicConfig } from "@/lib/runtime-config.shared";
import { readBoolEnv, readEnv } from "@/lib/runtime-env";

// `connection()` forces a per-request runtime read (never build-snapshotted);
// only this allowlist reaches the client. Each migrated key falls back to its
// deprecated NEXT_PUBLIC_* name during migration (see readEnv). Gated
// integrations (Sentry/GTM/PostHog) resolve to their value only when the
// matching UI_*_ENABLED flag is "true", else null — boot validation
// (lib/env.ts) guarantees the value is present whenever the flag is set.
export async function getRuntimePublicConfig(): Promise<RuntimePublicConfig> {
  await connection();

  return {
    sentryDsn: readGatedEnv(
      "UI_SENTRY_ENABLED",
      "UI_SENTRY_DSN",
      "NEXT_PUBLIC_SENTRY_DSN",
    ),
    sentryEnvironment: readGatedEnv(
      "UI_SENTRY_ENABLED",
      "UI_SENTRY_ENVIRONMENT",
      "NEXT_PUBLIC_SENTRY_ENVIRONMENT",
    ),
    googleTagManagerId: readGatedEnv(
      "UI_GOOGLE_TAG_MANAGER_ENABLED",
      "UI_GOOGLE_TAG_MANAGER_ID",
      "NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID",
    ),
    apiBaseUrl: readEnv("UI_API_BASE_URL", "NEXT_PUBLIC_API_BASE_URL"),
    apiDocsUrl: readEnv("UI_API_DOCS_URL", "NEXT_PUBLIC_API_DOCS_URL"),
    posthogKey: readGatedEnv(
      "UI_POSTHOG_ENABLED",
      "UI_POSTHOG_KEY",
      "POSTHOG_KEY",
    ),
    posthogHost: readGatedEnv(
      "UI_POSTHOG_ENABLED",
      "UI_POSTHOG_HOST",
      "POSTHOG_HOST",
    ),
    reoDevClientId: readEnv("REO_DEV_CLIENT_ID"),
    cloudEnabled: readBoolEnv("UI_CLOUD_ENABLED"),
    // Install-level selector "legacy" | "metronome" | "false"; the client only
    // needs on/off, so expose a derived boolean (the raw selector is read
    // server-side for V1/V2 routing). Default (unset) is off.
    cloudBillingEnabled:
      (readEnv("CLOUD_BILLING_ENABLED") ?? "false") !== "false",
    stripePublishableKey: readEnv(
      "UI_CLOUD_STRIPE_PUBLISHABLE_KEY",
      "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
    ),
    stripePublishableKeyV2: readEnv(
      "UI_CLOUD_STRIPE_PUBLISHABLE_KEY_V2",
      "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY_V2",
    ),
  };
}
