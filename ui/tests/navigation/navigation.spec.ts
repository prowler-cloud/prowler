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
});
