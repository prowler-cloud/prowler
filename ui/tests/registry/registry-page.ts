import { expect, type Locator, type Page } from "@playwright/test";

import { BasePage } from "../base-page";

export class RegistryPage extends BasePage {
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
    await expect(this.page).not.toHaveURL(/\/registry(?:\?|$)/);
    await expect(
      this.page.getByRole("heading", { name: "Profile" }),
    ).toBeVisible();
  }

  async verifyRegistryNavigationVisible(): Promise<void> {
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
      this.page.getByRole("main").getByText("API key connected"),
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
      .click();
    await this.page.getByRole("option", { name: "AWS" }).click();
    await expect(sharedPolicyCard).toBeVisible();

    // The multi-provider artifact stays reachable through every provider it serves.
    await this.page
      .getByRole("combobox", { name: "Filter by provider" })
      .click();
    await this.page.getByRole("option", { name: "Google Cloud" }).click();
    await expect(sharedPolicyCard).toBeVisible();
    await expect(networkAuditCard).toBeHidden();

    await this.page
      .getByRole("combobox", { name: "Filter by provider" })
      .click();
    await this.page.getByRole("option", { name: "All providers" }).click();
    await this.searchInput.clear();
    await expect(networkAuditCard).toBeVisible();
  }

  async verifyOwnerRows(): Promise<void> {
    // Logo-backed owner renders its image; the logo-less owner falls back to
    // an initial avatar, so only its name is asserted.
    await expect(this.page.getByText("Prowler Fixtures")).toBeVisible();
    await expect(this.page.locator('img[src*="owner-logo.png"]')).toBeVisible();
    await expect(this.page.getByText("Community Fixtures")).toBeVisible();
  }

  async verifyBuiltInArtifactIsAddable(name: string): Promise<void> {
    const card = this.artifactCardFor(name);

    await expect(card.getByRole("status", { name: "Built in" })).toBeVisible();
    await expect(
      card.getByRole("button", { name: `Add ${name}` }),
    ).toBeVisible();
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
    const dismissButton = this.page.getByRole("button", { name: "Got it" });
    if (await dismissButton.isVisible()) await dismissButton.click();
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
}
