import { readBoolEnv, readEnv } from "@/lib/runtime-env";

// Single source of truth for the third-party integrations gated behind a
// UI_*_ENABLED flag. The same map drives boot validation (lib/env.ts) and the
// runtime-config gating (lib/runtime-config.ts) so the two cannot drift.
//
// Two activation paths, applied uniformly to every integration:
//   - New `UI_*` names count only when the enable flag is "true" (explicit
//     opt-in; default off ⇒ no third-party egress).
//   - Legacy names stay backward compatible: their presence activates the
//     integration regardless of the flag, matching the pre-enable-flag
//     behavior, so an existing deployment keeps working untouched. A partial
//     legacy config fails fast (all required legacy names must be set), just
//     like an enabled one.
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
    enableKey: "UI_SENTRY_ENABLED",
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
    enableKey: "UI_GOOGLE_TAG_MANAGER_ENABLED",
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
    enableKey: "UI_POSTHOG_ENABLED",
    required: [
      { key: "UI_POSTHOG_KEY", legacy: "POSTHOG_KEY" },
      { key: "UI_POSTHOG_HOST", legacy: "POSTHOG_HOST" },
    ],
    optional: [],
  },
} as const satisfies Record<string, GatedIntegration>;

// Resolve a config value honoring the gate. The new `primary` (UI_*) name is
// read only when the enable flag is "true"; the `legacy` name is read
// regardless of the flag so a pre-existing deployment keeps working. When the
// flag is "true" the new name wins, falling back to the legacy name.
export function readGatedEnv(
  enableKey: keyof NodeJS.ProcessEnv,
  primary: keyof NodeJS.ProcessEnv,
  legacy?: keyof NodeJS.ProcessEnv,
): string | null {
  const legacyValue = legacy ? readEnv(legacy) : null;
  return readBoolEnv(enableKey)
    ? (readEnv(primary) ?? legacyValue)
    : legacyValue;
}

// True when every required var has a legacy name and all are set — the
// backward-compatible activation path that works without the enable flag.
function hasCompleteLegacyConfig(integration: GatedIntegration): boolean {
  return (
    integration.required.length > 0 &&
    integration.required.every(({ legacy }) => legacy && readEnv(legacy))
  );
}

// True when any required legacy name is set, i.e. the deployment is attempting
// legacy activation (possibly half-configured).
function hasAnyLegacyConfig(integration: GatedIntegration): boolean {
  return integration.required.some(({ legacy }) => legacy && readEnv(legacy));
}

// Boot-time fail-fast for an incomplete required config. When the flag is
// "true", each required var must resolve via its UI_* name or legacy fallback.
// When the flag is not set but a legacy name is present, the deployment is on
// the legacy path, so the full legacy set is required. Optional vars are never
// checked.
export function assertGatedIntegrations(): void {
  for (const integration of Object.values(GATED_INTEGRATIONS)) {
    if (readBoolEnv(integration.enableKey)) {
      for (const { key, legacy } of integration.required) {
        if (!readEnv(key, legacy)) {
          throw new Error(
            `Missing required env: ${key} (${integration.enableKey} is "true")`,
          );
        }
      }
      continue;
    }
    if (!hasAnyLegacyConfig(integration)) continue;
    for (const { legacy } of integration.required) {
      if (!legacy || !readEnv(legacy)) {
        throw new Error(
          `Missing required env: ${legacy ?? "legacy name"} (legacy ${integration.name} configuration is incomplete)`,
        );
      }
    }
  }
}

// Non-fatal nudge: a new UI_* value is set but the integration will not load
// because its enable flag is not "true" and it is not activated through a
// complete legacy config. Legacy-only deployments load and are not warned.
export function warnGatedIntegrationsMisconfig(): void {
  for (const integration of Object.values(GATED_INTEGRATIONS)) {
    if (readBoolEnv(integration.enableKey)) continue;
    if (hasCompleteLegacyConfig(integration)) continue;
    for (const { key } of [...integration.required, ...integration.optional]) {
      if (readEnv(key)) {
        // eslint-disable-next-line no-console
        console.warn(
          `${key} is set but ${integration.enableKey} is not "true"; ${integration.name} will not load.`,
        );
      }
    }
  }
}
