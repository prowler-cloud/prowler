import { readBoolEnv, readEnv } from "@/lib/runtime-env";

// Single source of truth for the third-party integrations gated behind a
// UI_*_ENABLE flag. The same map drives boot validation (lib/env.ts) and the
// runtime-config gating (lib/runtime-config.ts) so the two cannot drift:
// `required` vars throw at boot when the flag is "true" but they are unset;
// `optional` vars are gated/exposed but never throw.
interface IntegrationEnvVar {
  key: keyof NodeJS.ProcessEnv;
  legacy?: keyof NodeJS.ProcessEnv;
}

interface GatedIntegration {
  name: string;
  enableKey: keyof NodeJS.ProcessEnv;
  required: ReadonlyArray<IntegrationEnvVar>;
  optional: ReadonlyArray<IntegrationEnvVar>;
}

export const GATED_INTEGRATIONS: Record<string, GatedIntegration> = {
  sentry: {
    name: "Sentry",
    enableKey: "UI_SENTRY_ENABLE",
    required: [{ key: "UI_SENTRY_DSN", legacy: "NEXT_PUBLIC_SENTRY_DSN" }],
    optional: [
      {
        key: "UI_SENTRY_ENVIRONMENT",
        legacy: "NEXT_PUBLIC_SENTRY_ENVIRONMENT",
      },
    ],
  },
  googleTagManager: {
    name: "Google Tag Manager",
    enableKey: "UI_GOOGLE_TAG_MANAGER_ENABLE",
    required: [
      {
        key: "UI_GOOGLE_TAG_MANAGER_ID",
        legacy: "NEXT_PUBLIC_GOOGLE_TAG_MANAGER_ID",
      },
    ],
    optional: [],
  },
  posthog: {
    name: "PostHog",
    enableKey: "UI_POSTHOG_ENABLE",
    required: [{ key: "POSTHOG_KEY" }, { key: "POSTHOG_HOST" }],
    optional: [],
  },
} as const satisfies Record<string, GatedIntegration>;

// Resolve a config value only when its enable flag is "true"; otherwise null, so
// every presence-based consumer treats a disabled integration as unconfigured
// (DSN/id/key become null ⇒ no init ⇒ zero egress).
export function readGatedEnv(
  enableKey: keyof NodeJS.ProcessEnv,
  primary: keyof NodeJS.ProcessEnv,
  legacy?: keyof NodeJS.ProcessEnv,
): string | null {
  return readBoolEnv(enableKey) ? readEnv(primary, legacy) : null;
}

// Boot-time fail-fast: when an integration is enabled, every required var must
// resolve, else the container is misconfigured. Optional vars are not checked.
export function assertGatedIntegrations(): void {
  for (const integration of Object.values(GATED_INTEGRATIONS)) {
    if (!readBoolEnv(integration.enableKey)) continue;
    for (const { key, legacy } of integration.required) {
      if (!readEnv(key, legacy)) {
        throw new Error(
          `Missing required env: ${key} (${integration.enableKey} is "true")`,
        );
      }
    }
  }
}

// Non-fatal nudge for the default-off migration: a config value is set but its
// enable flag is not "true", so the integration silently will not load.
export function warnGatedIntegrationsMisconfig(): void {
  for (const integration of Object.values(GATED_INTEGRATIONS)) {
    if (readBoolEnv(integration.enableKey)) continue;
    for (const { key, legacy } of [
      ...integration.required,
      ...integration.optional,
    ]) {
      if (readEnv(key, legacy)) {
        // eslint-disable-next-line no-console
        console.warn(
          `${key} is set but ${integration.enableKey} is not "true"; ${integration.name} will not load.`,
        );
      }
    }
  }
}
