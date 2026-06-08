import "server-only";

import { connection } from "next/server";

import type { RuntimePublicConfig } from "@/lib/runtime-config.shared";
import { readEnv } from "@/lib/runtime-env";

// `connection()` forces a per-request runtime read (never build-snapshotted);
// only this allowlist reaches the client. Each migrated key falls back to its
// deprecated NEXT_PUBLIC_* name during migration (see readEnv).
export async function getRuntimePublicConfig(): Promise<RuntimePublicConfig> {
  await connection();

  return {
    sentryDsn: readEnv("UI_SENTRY_DSN", "NEXT_PUBLIC_SENTRY_DSN"),
    sentryEnvironment: readEnv(
      "UI_SENTRY_ENVIRONMENT",
      "NEXT_PUBLIC_SENTRY_ENVIRONMENT",
    ),
    googleTagManagerId: readEnv(
      "UI_GOOGLE_TAG_MANAGER_ID",
      "NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID",
    ),
    apiBaseUrl: readEnv("UI_API_BASE_URL", "NEXT_PUBLIC_API_BASE_URL"),
    apiDocsUrl: readEnv("UI_API_DOCS_URL", "NEXT_PUBLIC_API_DOCS_URL"),
    posthogKey: readEnv("POSTHOG_KEY"),
    posthogHost: readEnv("POSTHOG_HOST"),
    reoDevClientId: readEnv("REO_DEV_CLIENT_ID"),
  };
}
