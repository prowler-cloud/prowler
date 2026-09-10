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
  !readBoolEnv("UI_POSTHOG_ENABLED")
) {
  throw new Error(
    'CLOUD_BILLING_ENABLED is "metronome" but UI_POSTHOG_ENABLED is not "true"; PostHog is required for per-tenant billing routing.',
  );
}

warnGatedIntegrationsMisconfig();

// The billing UI is Cloud-only: navigation (navigation-config.ts) and the
// /billing route (proxy.ts) additionally gate on the cloud flag, so billing
// enabled without it is inert — warn, don't throw.
const cloudEnabled = readBoolEnv("UI_CLOUD_ENABLED");
const cloudBillingSelector = readEnv("CLOUD_BILLING_ENABLED");
const cloudBillingOn =
  cloudBillingSelector !== null && cloudBillingSelector !== "false";

if (cloudBillingOn && !cloudEnabled) {
  // eslint-disable-next-line no-console
  console.warn(
    `CLOUD_BILLING_ENABLED is "${cloudBillingSelector}" but UI_CLOUD_ENABLED is not "true"; the billing UI will not be shown.`,
  );
}

// Stripe publishable keys load only on billing flows; a key without billing
// enabled is inert.
if (!cloudBillingOn) {
  for (const name of [
    "UI_CLOUD_STRIPE_PUBLISHABLE_KEY",
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY",
    "UI_CLOUD_STRIPE_PUBLISHABLE_KEY_V2",
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY_V2",
  ] as const) {
    if (readEnv(name)) {
      // eslint-disable-next-line no-console
      console.warn(
        `${name} is set but CLOUD_BILLING_ENABLED is not enabled; Stripe will not load.`,
      );
    }
  }
}

export {};
