import { expect, type Locator, type Page, test } from "@playwright/test";

import { BasePage } from "../base-page";

export class RegistryPage extends BasePage {
  async captureEvidence(name: string): Promise<void> {
    const path = test.info().outputPath(`${name}.png`);
    await this.page.screenshot({
      path,
      fullPage: true,
      animations: "disabled",
    });
    await test.info().attach(name, { path, contentType: "image/png" });
  }
  readonly connectButton: Locator;
  readonly connectDialog: Locator;
  readonly exploreTab: Locator;
  readonly myArtifactsTab: Locator;
  readonly registryKeyInput: Locator;
  readonly registryLink: Locator;
  readonly searchInput: Locator;

  constructor(page: Page) {
    super(page);
    this.connectButton = page.getByRole("button", {
      name: "Connect API key",
    });
    this.connectDialog = page.getByRole("dialog", {
      name: "Connect Registry",
    });
    this.exploreTab = page.getByRole("tab", { name: /Explore/ });
    this.myArtifactsTab = page.getByRole("tab", { name: /My artifacts/ });
    this.registryKeyInput = page.getByLabel("Registry key");
    this.registryLink = page.getByRole("link", { name: "Registry" });
    this.searchInput = page.getByLabel("Search artifacts");
  }

  async goto(): Promise<void> {
    await super.goto("/registry");
    await this.dismissWelcomeDialog();
  }

  artifactCardFor(name: string): Locator {
    return this.page
      .getByRole("listitem")
      .filter({ has: this.page.getByText(name, { exact: true }) });
  }

  addButtonFor(name: string): Locator {
    return this.page.getByRole("button", { name: `Add ${name}` });
  }

  removeButtonFor(name: string): Locator {
    return this.page.getByRole("button", { name: `Remove ${name}` });
  }

  async verifyDirectRouteDenied(): Promise<void> {
    await this.dismissWelcomeDialog();
    await expect(this.page).not.toHaveURL(/\/registry(?:\?|$)/);
    await expect(
      this.page.getByRole("heading", { name: "Profile" }),
    ).toBeVisible();
  }

  async verifyRegistryNavigationVisible(): Promise<void> {
    await this.dismissWelcomeDialog();
    await expect(this.registryLink).toBeVisible();
  }

  async verifyRegistryNavigationHidden(): Promise<void> {
    await expect(this.registryLink).toBeHidden();
  }

  async verifyOnboarding(): Promise<void> {
    await expect(this.connectButton).toBeVisible();
    await expect(
      this.page.getByRole("link", {
        name: "Explore Prowler Registry (opens in a new tab)",
      }),
    ).toBeVisible();
  }

  async verifyMarketplaceReady(): Promise<void> {
    await expect(this.exploreTab).toBeVisible();
    await expect(
      this.page.getByRole("button", { name: "Manage access" }),
    ).toBeVisible();
  }

  async submitRegistryKey(key: string): Promise<void> {
    await this.connectButton.click();
    await expect(this.connectDialog).toBeVisible();
    await expect(this.registryKeyInput).toBeFocused();
    await this.registryKeyInput.fill(key);
    await this.page
      .getByRole("button", { name: "Connect", exact: true })
      .click();
  }

  async connectFixtureRegistry(): Promise<void> {
    await this.dismissWelcomeDialog();
    await this.verifyOnboarding();
    await this.submitRegistryKey("fixture-registry-key-not-a-secret");
    await this.verifyMarketplaceReady();
  }

  async verifyCompleteCatalogSearchAndFilters(): Promise<void> {
    const sharedPolicyCard = this.page.getByText("Fixture shared policy", {
      exact: true,
    });
    const networkAuditCard = this.page.getByText("Fixture network audit", {
      exact: true,
    });
    await this.searchInput.fill("shared");
    await expect(sharedPolicyCard).toBeVisible();

    await this.page
      .getByRole("combobox", { name: "Filter by provider" })
      .press("Enter");
    await this.page.getByRole("option", { name: "AWS", exact: true }).click();
    await expect(this.page).toHaveURL(/filter%5Bprovider%5D=aws/);
    await this.page.keyboard.press("Escape");
    await expect(sharedPolicyCard).toBeVisible();

    // The multi-provider artifact stays reachable through every provider it serves.
    await this.page
      .getByRole("combobox", { name: "Filter by provider" })
      .press("Enter");
    await this.page
      .getByRole("option", { name: "Google Cloud", exact: true })
      .click();
    await this.page.keyboard.press("Escape");
    await expect(sharedPolicyCard).toBeVisible();
    await expect(networkAuditCard).toBeHidden();

    await this.page
      .getByRole("button", { name: "Clear filters", exact: true })
      .click();
    await expect(networkAuditCard).toBeVisible();
  }

  async verifyOwnerRows(): Promise<void> {
    // Logo-backed owner renders its image; the logo-less owner falls back to
    // an initial avatar, so only its name is asserted.
    await expect(this.page.getByText("Prowler Fixtures")).toBeVisible();
    await expect(
      this.page.locator('img[src$="/fixture-owner.svg"]'),
    ).toBeVisible();
    await expect(this.page.getByText("Community Fixtures")).toBeVisible();
  }

  async verifyBuiltInArtifactHasNoAdd(name: string): Promise<void> {
    const card = this.artifactCardFor(name);

    await expect(card.getByRole("status", { name: "Built in" })).toBeVisible();
    await expect(
      card.getByRole("button", { name: `Add ${name}` }),
    ).toBeHidden();
  }

  async addLatest(name: string): Promise<void> {
    await this.addButtonFor(name).click();
    await expect(
      this.artifactCardFor(name).getByText("Added", { exact: true }),
    ).toBeVisible();
  }

  async verifyAddedInMyArtifacts(name: string): Promise<void> {
    await this.myArtifactsTab.click();
    await expect(this.removeButtonFor(name)).toBeVisible();
  }

  async removeArtifact(name: string): Promise<void> {
    await this.removeButtonFor(name).click();
    await expect(
      this.page.getByRole("button", { name: "Cancel" }),
    ).toBeFocused();
    await this.page.getByRole("button", { name: "Confirm Remove" }).click();
    await expect(
      this.page.getByText("Artifact removed", { exact: true }),
    ).toBeVisible();
  }

  async dismissWelcomeDialog(): Promise<void> {
    for (const name of ["Got it", "Skip for now"]) {
      const dismiss = this.page.getByRole("button", { name, exact: true });
      if (
        await dismiss
          .waitFor({ state: "visible", timeout: 1500 })
          .then(() => true)
          .catch(() => false)
      )
        await dismiss.click({ timeout: 2000 }).catch(async () => {
          // A route transition can unmount the welcome popover while it animates.
          await expect(dismiss).toBeHidden();
        });
    }
  }

  async verifyKeyIsNotDisclosed(
    key: string,
    requestUrls: string[],
  ): Promise<void> {
    await expect(this.page).not.toHaveURL(new RegExp(key, "u"));
    await expect(this.page.locator("body")).not.toContainText(key);
    expect(requestUrls).not.toContain(key);

    const storedValues = await this.page.evaluate(() => [
      ...Object.values(localStorage),
      ...Object.values(sessionStorage),
    ]);
    expect(storedValues).not.toContain(key);
  }
  async connectInstalledProviderAndScan(): Promise<void> {
    await this.page.getByRole("link", { name: "Go to Providers" }).click();
    await expect(this.page).toHaveURL(/\/providers$/);
    await this.dismissWelcomeDialog();
    await this.page.getByRole("button", { name: /Add (a )?Provider/i }).click();
    await expect(
      this.page.getByRole("option", { name: "Fixture Cloud Registry" }),
    ).toBeVisible();
    await this.page
      .getByRole("option", { name: "Fixture Cloud Registry" })
      .scrollIntoViewIfNeeded();
    await this.captureEvidence("registry-provider-selector");
    await this.page
      .getByRole("option", { name: "Fixture Cloud Registry" })
      .click();
    await this.page
      .getByLabel("Provider UID", { exact: true })
      .fill("fixture-account");
    await this.page
      .getByLabel("Provider alias (optional)")
      .fill("Registry test account");
    await this.page.getByRole("button", { name: "Next", exact: true }).click();
    const token = this.page.getByLabel("API token", { exact: false });
    await expect(token).toBeVisible();
    await this.captureEvidence("registry-provider-credentials");
    await token.fill("fixture-provider-token-not-a-secret");
    await this.page
      .getByRole("button", { name: "Authenticate", exact: true })
      .click();
    await this.page
      .getByRole("button", { name: "Check connection", exact: true })
      .click();
    await this.page
      .getByRole("radio", { name: "Run now", exact: true })
      .click();
    await this.page
      .getByRole("button", { name: "Launch scan", exact: true })
      .click();
    await expect(
      this.page.getByText("Scan launched", { exact: true }),
    ).toBeVisible();
    await this.page.goto("/scans?tab=completed");
    await expect(
      this.page.getByText("Fixture Registry scan", { exact: true }),
    ).toBeVisible();
    await expect(
      this.page
        .getByRole("row")
        .filter({ hasText: "Fixture Registry scan" })
        .getByText("Registry test account", { exact: true }),
    ).toBeVisible();
    await this.captureEvidence("registry-provider-scan-completed");
  }
}
