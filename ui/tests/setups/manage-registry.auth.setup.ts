import { test as authManageRegistrySetup } from "@playwright/test";

import { RegistryPage } from "../registry/registry-page";
import { SignInPage } from "../sign-in-base/sign-in-base-page";

const manageRegistryUserFile = "playwright/.auth/manage_registry_user.json";
const fixtureMode = process.env.E2E_REGISTRY_ACCEPTANCE_MODE === "fixture";

const fixtureCredentials = {
  email: "registry-fixture-user@example.test",
  password: "fixture-password-not-a-secret",
};

authManageRegistrySetup(
  "authenticate as Registry manager fixture user",
  async ({ page }) => {
    authManageRegistrySetup.skip(
      !fixtureMode,
      "Registry manager authentication is available only in self-contained fixture mode.",
    );

    const signInPage = new SignInPage(page);
    await signInPage.goto();
    await signInPage.login(fixtureCredentials);
    await page.waitForURL("/");
    await new RegistryPage(page).dismissWelcomeDialog();
    await signInPage.verifySuccessfulLogin();
    await page.context().storageState({ path: manageRegistryUserFile });
  },
);
