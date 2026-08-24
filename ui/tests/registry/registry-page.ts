import { expect, type Locator, type Page } from "@playwright/test";

import { BasePage } from "../base-page";

interface RegistryCatalogSelection {
  latestVersion: string;
  name: string;
}

export class RegistryPage extends BasePage {
  readonly addButton: Locator;
  readonly browseArtifactsButton: Locator;
  readonly connectButton: Locator;
  readonly connectDialog: Locator;
  readonly registryKeyInput: Locator;
  readonly registryLink: Locator;
  readonly registryNavigation: Locator;
  readonly removeButton: Locator;

  constructor(page: Page) {
    super(page);
    this.addButton = page.getByRole("button", { name: "Add" });
    this.browseArtifactsButton = page.getByRole("button", {
      name: "Browse artifacts",
    });
    this.connectButton = page.getByRole("button", {
      name: "Connect Registry",
    });
    this.connectDialog = page.getByRole("dialog", {
      name: "Connect Registry",
    });
    this.registryKeyInput = page.getByLabel("Registry key");
    this.registryLink = page.getByRole("link", { name: "Registry" });
    this.registryNavigation = page.getByLabel("Registry explorer");
    this.removeButton = page.getByRole("button", { name: "Remove" });
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
        name: "Open Registry (opens in a new tab)",
      }),
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
    await expect(
      this.page.getByRole("heading", { name: "Registry overview" }),
    ).toBeVisible();
  }

  async verifyCompleteCatalogSearchAndMultiProvider(): Promise<void> {
    const search = this.page.getByLabel("Search Registry artifacts");
    await search.fill("shared");
    await expect(
      this.page.getByRole("main").getByText("Fixture shared policy"),
    ).toBeVisible();

    await this.page
      .getByRole("combobox", { name: "Filter by provider" })
      .click();
    await this.page.getByRole("option", { name: "AWS" }).click();
    await expect(
      this.page.getByRole("main").getByText("Fixture shared policy"),
    ).toBeVisible();

    await this.page
      .getByRole("combobox", { name: "Filter by provider" })
      .click();
    await this.page.getByRole("option", { name: "All providers" }).click();
    await search.clear();
    await this.registryNavigation
      .getByText("Multi-provider", { exact: true })
      .click();
    const multiProviderOverview = this.page.getByRole("region", {
      name: "multi-provider artifacts",
    });
    await expect(multiProviderOverview).toBeVisible();
    await expect(
      multiProviderOverview.getByText("Fixture shared policy"),
    ).toBeVisible();
  }

  async verifyMyVersionSpec(version: string): Promise<void> {
    await expect(
      this.page.getByText(`My version specification: ${version}`),
    ).toBeVisible();
  }

  async selectMobileFixtureArtifact(): Promise<void> {
    const browseDialog = this.page.getByRole("dialog", {
      name: "Browse artifacts",
    });
    const mobileNavigation = browseDialog.getByLabel("Registry explorer");
    const awsGroup = mobileNavigation
      .getByRole("treeitem")
      .filter({ hasText: "AWS" })
      .first();
    if ((await awsGroup.getAttribute("aria-expanded")) === "false") {
      await awsGroup.getByRole("button", { name: "Expand" }).click();
    }

    const artifact = mobileNavigation.getByRole("treeitem", {
      name: "Fixture network audit",
    });
    await artifact.focus();
    await artifact.click();
    await expect(browseDialog).toBeHidden();
    await expect(
      this.page.getByRole("heading", { name: "Fixture network audit" }),
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

  async selectArtifact(name: string): Promise<void> {
    await this.registryNavigation.getByText(name, { exact: true }).click();
    await expect(this.page.getByRole("heading", { name })).toBeVisible();
  }

  async selectDeterministicArtifactWithLatestVersion(): Promise<RegistryCatalogSelection> {
    const availableRoot = this.registryNavigation
      .getByRole("treeitem")
      .filter({ hasText: "Available artifacts" })
      .first();
    await expect(availableRoot).toHaveAttribute("aria-expanded", "true");

    const availableTree = availableRoot.locator("xpath=..");
    const collapsedGroups = availableTree.locator(
      '[role="treeitem"][aria-expanded="false"]',
    );
    while (await collapsedGroups.count()) {
      await collapsedGroups
        .first()
        .getByRole("button", { name: "Expand" })
        .click();
    }

    const artifactLeaves = availableTree.locator(
      '[role="treeitem"]:not([aria-expanded])',
    );
    for (let index = 0; index < (await artifactLeaves.count()); index += 1) {
      const artifactLeaf = artifactLeaves.nth(index);
      const name = (await artifactLeaf.innerText()).trim();
      await artifactLeaf.press("Enter");
      const latestVersionText = await this.page
        .getByText(/^Latest version: /)
        .textContent();
      const latestVersion = latestVersionText
        ?.replace("Latest version: ", "")
        .trim();

      if (
        name &&
        latestVersion &&
        latestVersion !== "Not supplied" &&
        (await this.addButton.isVisible())
      ) {
        return { name, latestVersion };
      }
    }

    throw new Error(
      "Controlled Registry catalog has no available artifact with an exposed latest version.",
    );
  }

  async addLatest(): Promise<void> {
    await this.addButton.click();
    await this.page.getByRole("button", { name: "Add artifact" }).click();
    await expect(
      this.page.getByText("Artifact added", { exact: true }),
    ).toBeVisible();
  }

  async addExactVersion(version: string): Promise<void> {
    await this.addButton.click();
    await this.page.getByLabel("Use an exact version").check();
    await this.page.getByLabel("Exact version pin").fill(version);
    await this.page.getByRole("button", { name: "Add artifact" }).click();
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
