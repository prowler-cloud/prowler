import {
  assertGatedIntegrations,
  warnGatedIntegrationsMisconfig,
} from "@/lib/integrations";
import { readBoolEnv, readEnv } from "@/lib/runtime-env";

// Boot-time required-env assertion so a misconfigured container fails fast
// with a clear message. A key with a deprecated legacy name is satisfied by
// either name (see readEnv).
const REQUIRED: ReadonlyArray<{
  key: keyof NodeJS.ProcessEnv;
  legacy?: keyof NodeJS.ProcessEnv;
}> = [
  { key: "UI_API_BASE_URL", legacy: "NEXT_PUBLIC_API_BASE_URL" },
  { key: "AUTH_URL" },
  { key: "AUTH_SECRET" },
];

for (const { key, legacy } of REQUIRED) {
  if (!readEnv(key, legacy)) {
    throw new Error(`Missing required env: ${key}`);
  }
}

assertGatedIntegrations();

// `metronome` billing evaluates the BILLING_SYSTEM_METRONOME PostHog flag per
// tenant, so PostHog must be enabled or every tenant would be misrouted to the
// wrong billing system. Fail fast instead of degrading silently.
if (
  readEnv("CLOUD_BILLING_ENABLED") === "metronome" &&
  !readBoolEnv("UI_POSTHOG_ENABLE")
) {
  throw new Error(
    'CLOUD_BILLING_ENABLED is "metronome" but UI_POSTHOG_ENABLE is not "true"; PostHog is required for per-tenant billing routing.',
  );
}

warnGatedIntegrationsMisconfig();

export {};
