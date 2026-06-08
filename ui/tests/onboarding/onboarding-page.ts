import { Locator, Page, expect } from "@playwright/test";

import { BasePage } from "../base-page";

const TOUR_KEY_PREFIX = "prowler.tour";
const ADD_PROVIDER_TOUR_KEY = `${TOUR_KEY_PREFIX}.add-provider.v1`;
const CHECKPOINT_MARKER_KEY = "prowler.onboarding.checkpoint";

// One popover per active driver.js tour; used to assert single-fire / no auto-fire.
const DRIVER_POPOVER_SELECTOR = ".driver-popover";

// POM for onboarding flows. URL assertions live here; the spec only orchestrates actions.
// Note: the sequence store is ephemeral (no persist) — a fresh goto/reload resets it.
export class OnboardingPage extends BasePage {
  readonly welcomeModal: Locator;
  readonly getStartedButton: Locator;
  readonly skipButton: Locator;

  readonly checkpointDialog: Locator;
  readonly checkpointContinueButton: Locator;
  readonly checkpointFinishButton: Locator;

  readonly addProviderTriggerAnchor: Locator;
  readonly providerTypeAnchor: Locator;

  readonly viewFirstScanLaunchAnchor: Locator;
  readonly viewFirstScanTabsAnchor: Locator;
  readonly exploreFindingsFiltersAnchor: Locator;
  readonly exploreFindingsTableAnchor: Locator;
  readonly viewComplianceFrameworksAnchor: Locator;
  readonly viewComplianceSearchAnchor: Locator;
  readonly attackPathsIntroAnchor: Locator;
  readonly attackPathsScanListAnchor: Locator;

  readonly accountMenuTrigger: Locator;
  readonly productTourSubTrigger: Locator;

  readonly driverPopover: Locator;

  constructor(page: Page) {
    super(page);

    this.welcomeModal = page.getByRole("dialog").filter({
      has: page.getByRole("heading", { name: /Add your first provider/i }),
    });
    this.getStartedButton = page.getByRole("button", { name: "Get started" });
    this.skipButton = page.getByRole("button", { name: "Skip for now" });

    this.checkpointDialog = page.getByRole("dialog").filter({
      has: page.getByRole("heading", {
        name: /Provider added — keep exploring\?/i,
      }),
    });
    this.checkpointContinueButton = page.getByRole("button", {
      name: "Continue the tour",
    });
    this.checkpointFinishButton = page.getByRole("button", {
      name: "Finish here",
    });

    this.addProviderTriggerAnchor = page.locator(
      '[data-tour-id="add-provider-trigger"]',
    );
    this.providerTypeAnchor = page.locator(
      '[data-tour-id="add-provider-provider-type"]',
    );

    this.viewFirstScanLaunchAnchor = page.locator(
      '[data-tour-id="view-first-scan-launch"]',
    );
    this.viewFirstScanTabsAnchor = page.locator(
      '[data-tour-id="view-first-scan-tabs"]',
    );
    this.exploreFindingsFiltersAnchor = page.locator(
      '[data-tour-id="explore-findings-filters"]',
    );
    this.exploreFindingsTableAnchor = page.locator(
      '[data-tour-id="explore-findings-table"]',
    );
    this.viewComplianceFrameworksAnchor = page.locator(
      '[data-tour-id="view-compliance-frameworks"]',
    );
    this.viewComplianceSearchAnchor = page.locator(
      '[data-tour-id="view-compliance-search"]',
    );
    this.attackPathsIntroAnchor = page.locator(
      '[data-tour-id="attack-paths-intro"]',
    );
    this.attackPathsScanListAnchor = page.locator(
      '[data-tour-id="attack-paths-scan-list"]',
    );

    this.accountMenuTrigger = page.getByRole("button", {
      name: "Account menu",
    });
    this.productTourSubTrigger = page.getByRole("menuitem", {
      name: "Product tour",
    });

    this.driverPopover = page.locator(DRIVER_POPOVER_SELECTOR);
  }

  // Clears all tour records and the checkpoint marker so the gate evaluates as a fresh browser.
  async clearOnboardingState(): Promise<void> {
    await this.page.evaluate(
      ({ prefix, checkpointKey }) => {
        const keys: string[] = [];
        for (let i = 0; i < window.localStorage.length; i++) {
          const key = window.localStorage.key(i);
          if (key && key.startsWith(prefix)) keys.push(key);
        }
        keys.forEach((key) => window.localStorage.removeItem(key));
        window.localStorage.removeItem(checkpointKey);
      },
      { prefix: TOUR_KEY_PREFIX, checkpointKey: CHECKPOINT_MARKER_KEY },
    );
  }

  // Seeds a completed record so the restart path can prove the tour re-fires anyway.
  async seedCompletedAddProviderRecord(): Promise<void> {
    await this.page.evaluate((key) => {
      window.localStorage.setItem(
        key,
        JSON.stringify({
          tourId: "add-provider",
          version: 1,
          state: "completed",
          completedAt: new Date().toISOString(),
        }),
      );
    }, ADD_PROVIDER_TOUR_KEY);
  }

  async openAccountMenu(): Promise<void> {
    await this.accountMenuTrigger.click();
  }

  // Hover the sub-trigger to open the per-flow submenu.
  async openProductTourSubmenu(): Promise<void> {
    await this.openAccountMenu();
    await expect(this.productTourSubTrigger).toBeVisible();
    await this.productTourSubTrigger.hover();
  }

  tourFlowMenuItem(title: string): Locator {
    return this.page.getByRole("menuitem", { name: title, exact: true });
  }

  async selectTourFlow(title: string): Promise<void> {
    await this.openProductTourSubmenu();
    const item = this.tourFlowMenuItem(title);
    await expect(item).toBeVisible();
    await item.click();
  }

  async clickGetStarted(): Promise<void> {
    await this.getStartedButton.click();
  }

  async clickCheckpointContinue(): Promise<void> {
    await this.checkpointContinueButton.click();
  }

  async clickCheckpointFinish(): Promise<void> {
    await this.checkpointFinishButton.click();
  }

  async closeActiveTour(): Promise<void> {
    await this.page.keyboard.press("Escape");
  }

  async verifyWelcomeModalVisible(): Promise<void> {
    await expect(this.welcomeModal).toBeVisible();
  }

  async verifyWelcomeModalNotVisible(): Promise<void> {
    await expect(this.welcomeModal).not.toBeVisible();
  }

  async verifyCheckpointDialogVisible(): Promise<void> {
    await expect(this.checkpointDialog).toBeVisible();
  }

  async verifyTriggerAnchorPresent(): Promise<void> {
    await expect(this.addProviderTriggerAnchor).toBeVisible();
  }

  async verifyAnchorsPresent(): Promise<void> {
    await expect(this.addProviderTriggerAnchor).toBeVisible();
    await expect(this.providerTypeAnchor).toBeVisible();
  }

  async verifyViewFirstScanAnchorPresent(): Promise<void> {
    await expect(this.viewFirstScanLaunchAnchor).toBeVisible();
  }

  async verifyExploreFindingsAnchorPresent(): Promise<void> {
    await expect(this.exploreFindingsFiltersAnchor).toBeVisible();
  }

  async verifyViewComplianceAnchorPresent(): Promise<void> {
    await expect(this.viewComplianceFrameworksAnchor).toBeVisible();
  }

  async verifyAttackPathsAnchorPresent(): Promise<void> {
    await expect(this.attackPathsIntroAnchor).toBeVisible();
  }

  // OB-E2E-006: page owns the driver; onboarding must not mount a second one.
  async verifySingleDriverPopover(): Promise<void> {
    await expect(this.driverPopover).toHaveCount(1);
  }

  // OB-E2E-007/004: no tour auto-fires after a reload or stop.
  async verifyNoDriverPopover(): Promise<void> {
    await expect(this.driverPopover).toHaveCount(0);
  }

  async verifyOnProvidersPage(): Promise<void> {
    await this.page.waitForURL(/\/providers(\?|$)/);
  }

  async verifyOnProvidersPageWithOnboardingParam(): Promise<void> {
    await this.page.waitForURL(/\/providers\?onboarding=add-provider/);
  }

  async verifyOnScansPage(): Promise<void> {
    await this.page.waitForURL(/\/scans(\?|$)/);
  }

  async verifyOnFindingsPage(): Promise<void> {
    await this.page.waitForURL(/\/findings(\?|$)/);
  }

  async verifyOnFindingsReplayPage(): Promise<void> {
    await this.page.waitForURL(/\/findings\?onboarding=explore-findings/);
  }

  async verifyOnCompliancePage(): Promise<void> {
    await this.page.waitForURL(/\/compliance(\?|$)/);
  }

  async verifyOnAttackPathsPage(): Promise<void> {
    await this.page.waitForURL(/\/attack-paths/);
  }

  async verifyStillOnFindingsPage(): Promise<void> {
    await expect(this.page).toHaveURL(/\/findings/);
  }
}
