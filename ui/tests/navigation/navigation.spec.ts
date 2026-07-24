import { test } from "@playwright/test";

import { NavigationPage } from "./navigation-page";

test.describe("App navigation", () => {
  test.use({ storageState: "playwright/.auth/admin_user.json" });

  test(
    "keeps the mobile sidebar and close control inside the viewport",
    {
      tag: ["@e2e", "@navigation", "@high", "@NAV-E2E-001"],
    },
    async ({ page }) => {
      const navigationPage = new NavigationPage(page);

      await navigationPage.goto();
      await navigationPage.verifyPageLoaded();
      await navigationPage.openMobileSidebar();
      await navigationPage.verifyMobileSidebarFitsViewport();
    },
  );

  test(
    "keeps authenticated navigation usable when PostHog is blocked",
    {
      tag: ["@e2e", "@navigation", "@high", "@NAV-E2E-002"],
    },
    async ({ page }) => {
      const navigationPage = new NavigationPage(page);

      // Resilience only: a PostHog network outage must not break authenticated
      // navigation. We deliberately do NOT assert on the feedback widget here.
      // It is enabled by the build-time-inlined NEXT_PUBLIC_POSTHOG_KEY, which
      // cannot be injected via the start-time webServer env, so it never renders
      // in E2E — asserting its presence is impossible and asserting its absence
      // would pass for the wrong reason. Its render/capture path is unit-tested
      // (components/survey/feedback-survey.test.tsx).
      await navigationPage.blockPostHogRequests();
      await navigationPage.goto();
      await navigationPage.verifyPageLoaded();
      await navigationPage.navigateToProviders();
      await navigationPage.verifyPageLoaded();
    },
  );
});

test.describe("Public navigation", () => {
  test.use({ storageState: { cookies: [], origins: [] } });

  test(
    "does not expose feedback on public routes",
    {
      tag: ["@e2e", "@navigation", "@high", "@NAV-E2E-003"],
    },
    async ({ page }) => {
      const navigationPage = new NavigationPage(page);

      // Meaningful gate independent of PostHog: FeedbackSurvey is mounted only in
      // the authenticated (prowler) layout, so it must never appear on public
      // routes — regardless of survey/key state. (Authenticated widget rendering
      // itself is unit-tested; NEXT_PUBLIC_POSTHOG_KEY is build-time inlined and
      // absent in E2E.)
      await navigationPage.gotoSignIn();
      await navigationPage.verifySignInPageLoaded();
      await navigationPage.verifyFeedbackTriggerAbsent();
    },
  );
});
