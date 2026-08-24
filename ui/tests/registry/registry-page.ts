import { expect, type Locator, type Page } from "@playwright/test";

import { BasePage } from "../base-page";

interface RegistryCatalogSelection {
  latestVersion: string;
  name: string;
}

export class RegistryPage extends BasePage {
  readonly addToWorkspaceButton: Locator;
  readonly artifactPanel: Locator;
  readonly connectButton: Locator;
  readonly connectDialog: Locator;
  readonly exploreTab: Locator;
  readonly myArtifactsTab: Locator;
  readonly registryKeyInput: Locator;
  readonly registryLink: Locator;
  readonly removeButton: Locator;
  readonly searchInput: Locator;

  constructor(page: Page) {
    super(page);
    this.addToWorkspaceButton = page.getByRole("button", {
      name: "Add to workspace",
    });
    this.artifactPanel = page.getByRole("dialog", { name: "Artifact details" });
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
    this.removeButton = page.getByRole("button", { name: "Remove" });
    this.searchInput = page.getByLabel("Search artifacts");
  }

  async goto(): Promise<void> {
    await super.goto("/registry");
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
    await expect(this.page.getByText("API key connected")).toBeVisible();
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
    const sharedPolicyCard = this.page.getByRole("button", {
      name: "Fixture shared policy",
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
    await expect(
      this.page.getByRole("button", {
        name: "Fixture network audit",
        exact: true,
      }),
    ).toBeHidden();

    await this.page
      .getByRole("combobox", { name: "Filter by provider" })
      .click();
    await this.page.getByRole("option", { name: "All providers" }).click();
    await this.searchInput.clear();
    await expect(
      this.page.getByRole("button", {
        name: "Fixture network audit",
        exact: true,
      }),
    ).toBeVisible();
  }

  async verifyMyVersionSpec(version: string): Promise<void> {
    await expect(
      this.page.getByText(`My version specification: ${version}`),
    ).toBeVisible();
  }

  async openArtifact(name: string): Promise<void> {
    await this.page.getByRole("button", { name, exact: true }).click();
    await expect(
      this.artifactPanel.getByRole("heading", { name }),
    ).toBeVisible();
  }

  async closeArtifactPanel(): Promise<void> {
    await this.artifactPanel.getByRole("button", { name: "Close" }).click();
    await expect(this.artifactPanel).toBeHidden();
  }

  async selectMobileFixtureArtifact(): Promise<void> {
    const card = this.page.getByRole("button", {
      name: "Fixture network audit",
      exact: true,
    });
    await card.focus();
    await card.press("Enter");
    await expect(
      this.artifactPanel.getByRole("heading", {
        name: "Fixture network audit",
      }),
    ).toBeFocused();
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

  async selectDeterministicArtifactWithLatestVersion(): Promise<RegistryCatalogSelection> {
    const addButtons = this.page.getByRole("button", {
      name: /^Add (?!to workspace)/,
    });
    const total = await addButtons.count();
    for (let index = 0; index < total; index += 1) {
      await addButtons.nth(index).click();
      await expect(this.artifactPanel).toBeVisible();
      const name = (
        await this.artifactPanel
          .getByRole("heading")
          .filter({ hasNotText: "Artifact details" })
          .innerText()
      ).trim();
      const latestVersion = (
        await this.artifactPanel
          .locator("dt", { hasText: "Latest version" })
          .locator("xpath=following-sibling::dd")
          .innerText()
      ).trim();

      if (name && latestVersion && latestVersion !== "Not supplied") {
        return { name, latestVersion };
      }
      await this.closeArtifactPanel();
    }

    throw new Error(
      "Controlled Registry catalog has no available artifact with an exposed latest version.",
    );
  }

  async addLatest(): Promise<void> {
    await this.addToWorkspaceButton.click();
    await expect(
      this.page.getByText("Artifact added", { exact: true }),
    ).toBeVisible();
  }

  async addExactVersion(version: string): Promise<void> {
    await this.page.getByLabel("Use an exact version").check();
    await this.page.getByLabel("Exact version pin").fill(version);
    await this.addToWorkspaceButton.click();
    await expect(
      this.page.getByText("Artifact added", { exact: true }),
    ).toBeVisible();
  }

  async removeArtifact(): Promise<void> {
    await this.removeButton.click();
    await expect(
      this.page.getByRole("button", { name: "Cancel" }),
    ).toBeFocused();
    await this.page.getByRole("button", { name: "Confirm Remove" }).click();
    await expect(
      this.page.getByText("Artifact removed", { exact: true }),
    ).toBeVisible();
  }
}
