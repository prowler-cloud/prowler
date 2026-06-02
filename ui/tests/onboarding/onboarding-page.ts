import { Locator, Page, expect } from "@playwright/test";

import { BasePage } from "../base-page";

// localStorage key prefix used by the tour completion store
// (`prowler.tour.<tourId>.v<version>`). Kept here so the cleanup helper never
// hand-builds keys elsewhere in the suite.
const TOUR_KEY_PREFIX = "prowler.tour";
const ADD_PROVIDER_TOUR_KEY = `${TOUR_KEY_PREFIX}.add-provider.v1`;
// Marker the checkpoint watcher sets once the user chooses continue/finish, so
// the dialog never re-appears in the same browser. Cleared per test.
const CHECKPOINT_MARKER_KEY = "prowler.onboarding.checkpoint";

// Driver.js renders exactly one popover per active tour instance. Counting these
// proves single-fire (OB-E2E-006) and "no auto-fire after reload" (OB-E2E-007).
const DRIVER_POPOVER_SELECTOR = ".driver-popover";

// Page Object for the onboarding flows. URL assertions live here (per the
// prowler-test-ui convention) so the spec only orchestrates user actions.
//
// Sequence-slice reset note: `useOnboardingSequenceStore` is an ephemeral,
// in-memory Zustand store (no `persist`). It resets on any full page load, so
// the suite never needs to clear it via localStorage — a fresh `goto`/`reload`
// is the reset. Only the checkpoint marker and the tour completion records are
// persisted, and `clearOnboardingState()` clears both.
export class OnboardingPage extends BasePage {
  // Welcome modal (mandatory gate entry point) and its actions.
  readonly welcomeModal: Locator;
  readonly getStartedButton: Locator;
  readonly skipButton: Locator;

  // Checkpoint dialog shown after the first provider connects (Decision 3).
  readonly checkpointDialog: Locator;
  readonly checkpointContinueButton: Locator;
  readonly checkpointFinishButton: Locator;

  // Tour anchor mounted on the providers surface. The add-provider tour ends at
  // the Add Provider button and never anchors inside the wizard.
  readonly addProviderTriggerAnchor: Locator;

  // Per-route anchors for the sequence flows (Slices 4-7). Each value is
  // `<tour-id>-<step.target>`, matching the `data-tour-id` produced by adaptStep.
  readonly viewFirstScanLaunchAnchor: Locator;
  readonly viewFirstScanTabsAnchor: Locator;
  readonly exploreFindingsFiltersAnchor: Locator;
  readonly exploreFindingsTableAnchor: Locator;
  readonly viewComplianceFrameworksAnchor: Locator;
  readonly viewComplianceSearchAnchor: Locator;
  readonly attackPathsIntroAnchor: Locator;
  readonly attackPathsScanListAnchor: Locator;

  // User-nav restart entry point: now a submenu (`DropdownMenuSub`) listing one
  // item per ordered flow. Radix renders the trigger as a `menuitem`.
  readonly accountMenuTrigger: Locator;
  readonly productTourSubTrigger: Locator;

  // Active driver popover(s). Used to assert single-fire / no auto-fire.
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
        name: /Provider connected — keep exploring\?/i,
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

  // Clear every `prowler.tour.*` key AND the checkpoint marker so the gate and
  // the checkpoint watcher both evaluate as a fresh browser.
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

  // Seed a `completed` record so the restart path proves the tour starts despite
  // an existing completion record.
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

  // Open the avatar menu and reveal the "Product tour" submenu. Hovering the
  // sub-trigger opens the sub-content where the per-flow items live.
  async openProductTourSubmenu(): Promise<void> {
    await this.openAccountMenu();
    await expect(this.productTourSubTrigger).toBeVisible();
    await this.productTourSubTrigger.hover();
  }

  // A per-flow replay item inside the "Product tour" submenu, addressed by its
  // flow title (e.g. "Explore your findings").
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

  // Close the active tour by pressing Escape (driver.js destroy = user-close).
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
  }

  // Each sequence route exposes its first anchor; the spec asserts that one to
  // prove the route's OnboardingTrigger surface is reachable.
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

  // OB-E2E-006: exactly one driver popover exists (page owns the driver; no
  // second runner from onboarding).
  async verifySingleDriverPopover(): Promise<void> {
    await expect(this.driverPopover).toHaveCount(1);
  }

  // OB-E2E-007 / OB-E2E-004: no tour auto-fires after a reload / stop.
  async verifyNoDriverPopover(): Promise<void> {
    await expect(this.driverPopover).toHaveCount(0);
  }

  // URL assertions encapsulated in the POM (prowler-test-ui convention).
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
