import { expect, test } from "@playwright/test";

import { RUNTIME_CONFIG_KEYS, RuntimeConfigPage } from "./runtime-config-page";

test.describe("Runtime public-config data island", () => {
  let runtimeConfigPage: RuntimeConfigPage;

  test.beforeEach(async ({ page }) => {
    runtimeConfigPage = new RuntimeConfigPage(page);
    await runtimeConfigPage.goto();
  });

  test(
    "renders an inert JSON island in <head> before the client bundle",
    {
      tag: ["@critical", "@e2e", "@runtime-config", "@RUNTIME-CONFIG-E2E-001"],
    },
    async () => {
      // The island exists, is inert (application/json), lives in <head>, and
      // precedes the first external bundle script (the ordering guarantee a
      // jsdom unit test cannot prove).
      await expect(runtimeConfigPage.island).toBeAttached();
      await runtimeConfigPage.verifyIslandInHead();
      await runtimeConfigPage.verifyIslandPrecedesClientBundle();

      // It carries exactly the allowlisted shape and parses as JSON.
      const config = await runtimeConfigPage.readConfig();
      expect(config).not.toBeNull();
      expect(Object.keys(config ?? {}).sort()).toEqual(
        [...RUNTIME_CONFIG_KEYS].sort(),
      );
      // API base URL is the required runtime value supplied to the server.
      expect(config?.apiBaseUrl).toBeTruthy();
    },
  );

  test(
    "browser Sentry init is consistent with the island DSN",
    { tag: ["@high", "@e2e", "@runtime-config", "@RUNTIME-CONFIG-E2E-002"] },
    async () => {
      // The island feeds instrumentation-client's Sentry.init race-free. Assert
      // the wiring regardless of whether this deployment configures a DSN:
      //  - DSN set   ⇒ Sentry initialized with that exact runtime DSN
      //  - DSN unset ⇒ Sentry not initialized (zero egress, the default)
      const config = await runtimeConfigPage.readConfig();
      const islandDsn = (config?.sentryDsn as string | null) ?? null;
      const initializedDsn = await runtimeConfigPage.sentryInitializedDsn();

      if (islandDsn) {
        expect(initializedDsn).toBe(islandDsn);
      } else {
        expect(initializedDsn).toBeNull();
      }
    },
  );

  test(
    "sends zero third-party telemetry when Sentry and GTM are unset",
    {
      tag: ["@critical", "@e2e", "@runtime-config", "@RUNTIME-CONFIG-E2E-003"],
    },
    async () => {
      // The Enterprise default: with neither integration configured, the page
      // must not contact Sentry or Google. Only meaningful when this deployment
      // actually leaves them unset.
      const config = await runtimeConfigPage.readConfig();
      test.skip(
        Boolean(config?.sentryDsn) || Boolean(config?.googleTagManagerId),
        "Sentry or GTM is configured in this environment",
      );

      const hits = await runtimeConfigPage.thirdPartyRequestsOnReload([
        "googletagmanager.com",
        "google-analytics.com",
        "sentry.io",
      ]);

      expect(hits).toEqual([]);
      await runtimeConfigPage.verifyGoogleTagManagerNotRendered();
    },
  );
});
