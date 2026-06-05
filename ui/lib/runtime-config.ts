import "server-only";

import { connection } from "next/server";

import type { RuntimePublicConfig } from "@/lib/runtime-config.shared";

const read = (value?: string): string | null =>
  value && value.trim() !== "" ? value : null;

// `connection()` forces a per-request runtime read (never build-snapshotted);
// only this allowlist reaches the client.
export async function getRuntimePublicConfig(): Promise<RuntimePublicConfig> {
  await connection();

  return {
    sentryDsn: read(process.env.WEB_APP_SENTRY_DSN),
    sentryEnvironment: read(process.env.WEB_APP_SENTRY_ENVIRONMENT),
    googleTagManagerId: read(process.env.WEB_APP_GOOGLE_TAG_MANAGER_ID),
    apiBaseUrl: read(process.env.WEB_APP_API_BASE_URL),
    apiDocsUrl: read(process.env.WEB_APP_API_DOCS_URL),
    posthogKey: read(process.env.POSTHOG_KEY),
    posthogHost: read(process.env.POSTHOG_HOST),
    reoDevClientId: read(process.env.REO_DEV_CLIENT_ID),
  };
}
